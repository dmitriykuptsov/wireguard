#!/usr/bin/python3

# Copyright (C) 2019 strangebit

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

__author__ = "Dmitriy Kuptsov"
__copyright__ = "Copyright 2025, strangebit"
__license__ = "GPL"
__version__ = "0.0.1b"
__maintainer__ = "Dmitriy Kuptsov"
__email__ = "dmitriy.kuptsov@gmail.com"
__status__ = "development"

# Import the needed libraries
# Stacktrace
import traceback
# Sockets
import socket
# Threading
import threading
# Logging
import logging
# Timing
import time
# Math functions
from math import ceil, floor
# System
import sys
# Exit handler
import atexit
# Tun interface
import crypto.aead
import crypto.constants
import crypto.curve25519
import crypto.digest
from network import tun
from network.pytun import TunTunnel
# Packets
import packets.packets as p
from packets.packets import WireGuardDataPacket, WireGuardResponderPacket, WireGuardInitiatorPacket, WireGuardPacket, WireGuardCookiePacket
from packets.IPv4 import IPv4Packet
# Statemachine classes
import routing.cryptoroute
from states import Statemachine
# Cryptography
import crypto
# OS stuff
import os
# Misc stuff
import utils.misc
# Cryptorouting table stuff
import routing
# Timing 
from time import time
from time import sleep
from config.config import Config
from base64 import b64encode, b64decode

# Configure logging to console and file
logging.basicConfig(
	level=logging.DEBUG,
	format="%(asctime)s [%(levelname)s] %(message)s",
	handlers=[
		logging.FileHandler("wg.log"),
		logging.StreamHandler(sys.stdout)
	]
);

config = Config("config/configuration.txt")
table = routing.cryptoroute.RoutingTable()

def config_loop():
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind(("127.0.0.1", 10000))
	s.listen(5)
	while True:
		reading = True
		conn, addr = s.accept()
		try:
			while reading:
				command = conn.recv(2000);
				command=command.decode("ASCII").strip()
				if command == "status":
					Spriv = crypto.curve25519.X25519PrivateKey.from_private_bytes(b64decode(config.get(Config.KEY)))
					Spub = Spriv.public_key()
					conn.send("Private key: ".encode("ASCII"))
					conn.send(b64encode(Spriv.private_bytes()))
					conn.send("\n".encode("ASCII"))
					conn.send("Public key: ".encode("ASCII"))					
					conn.send(b64encode(Spub))
					conn.send("\n".encode("ASCII"))
					conn.send("Peer: ".encode("ASCII"))
					conn.send(config.get(Config.PEER).encode("ASCII"))
					conn.send("\n".encode("ASCII"))
					conn.send("Port: ".encode("ASCII"))
					conn.send(config.get(Config.PORT).encode("ASCII"))
					conn.send("\n".encode("ASCII"))
				elif command.startswith("add route"):
					command = command.removeprefix("add route").strip()
					(ip, prefix, key, port, ip_s) = command.split(" ")
					logging.debug("Adding crypto routing entry....")
					logging.debug("IP:" + ip)
					logging.debug("Prefix: " + prefix)
					logging.debug("Key: " + key)
					logging.debug("Port: " + port)
					logging.debug("Destination: " + ip_s)
					ip_bytes = bytes([int(x) for x in ip.split(".")])
					prefix_bytes = bytes([int(x) for x in prefix.split(".")])
					port = int(port)
					entry = routing.cryptoroute.CryptoRoutingEntry(utils.misc.Math.bytes_to_int(ip_bytes), \
													utils.misc.Math.bytes_to_int(prefix_bytes), \
														b64decode(key), int(port), ip_s)
					table.add(entry)
				elif command.startswith("list routes"):
					for e in table.table:
						conn.send(str(e).encode("ASCII"))
						conn.send("\n".encode("ASCII"))
				elif command.strip() == "exit" or command.strip() == "":
					conn.close();
					reading = False;
		except Exception as e:
			logging.critical(e)
			conn.close()

wg_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
wg_socket.bind(('', 12000))
MTU = 1460

tun = TunTunnel(pattern = "wg0");
tun.set_ipv4(config.get(Config.PEER))
tun.set_mtu(MTU);

# Read this from file instead
Spriv = crypto.curve25519.X25519PrivateKey.from_private_bytes(b64decode(config.get(Config.KEY)))
Spub = Spriv.public_key()

def tun_loop():
	while True:
		data = tun.recv(MTU);
		logging.debug("Got packet on wg0...")
		ip = IPv4Packet(data);
		dst = utils.misc.Math.bytes_to_int(ip.get_destination_address());
		entry = table.get_by_ip(dst)
		if not entry:
			continue
		if entry.state != Statemachine.States.ESTABLISHED and entry.rekey_timeout <= time():
			Srpub = entry.key
			h = crypto.digest.Digest()
			Ci = h.digest(crypto.constants.CONSTRUCTION)
			h = crypto.digest.Digest()
			Hi = h.digest(Ci + crypto.constants.IDENTIFIER)
			h = crypto.digest.Digest()
			Hi = h.digest(Hi + Srpub)
			Epriv = crypto.curve25519.X25519PrivateKey.from_private_bytes(os.urandom(32))
			Epub = Epriv.public_key()
			Ci = crypto.digest.KDF.kdf1(Ci, Epub)
			packet = WireGuardInitiatorPacket()
			ri = os.urandom(4)
			packet.sender(ri)
			packet.ephimeral(Epub)
			h = crypto.digest.Digest()
			Hi = h.digest(Hi + packet.ephimeral())
			(Ci, k) = crypto.digest.KDF.kdf2(Ci, Epriv.exchange(crypto.curve25519.X25519PublicKey.from_public_bytes(Srpub)))
			aead = crypto.aead.AEAD(k, bytes([0x0] * 8))
			packet.static(aead.encrypt(Spub, Hi))
			h = crypto.digest.Digest()
			Hi = h.digest(Hi + packet.static())
			(Ci, k) = crypto.digest.KDF.kdf2(Ci, Spriv.exchange(crypto.curve25519.X25519PublicKey.from_public_bytes(Srpub)))
			aead = crypto.aead.AEAD(k, bytes([0x0] * 8))
			packet.timestamp(aead.encrypt(utils.misc.Math.tai64n(), Hi))
			h = crypto.digest.Digest()
			Hi = h.digest(Hi + packet.timestamp())
			entry.state = Statemachine.States.I_SENT
			entry.rekey_timeout = time() + Statemachine.RekeyTimeout
			entry.I = ri
			entry.Ci = Ci
			entry.Hi = Hi
			entry.Epub = Epub
			entry.Epriv = Epriv
			buffer = packet.buffer[:p.INITIATOR_MSG_ALPHA_OFFSET]
			h = crypto.digest.Digest()
			m = crypto.digest.MACDigest(h.digest(crypto.constants.LABEL_MAC1 + Spub), buffer)
			packet.mac1(m)
			wg_socket.sendto(packet.buffer, (entry.ip_s, entry.port))
		elif entry.state == Statemachine.States.ESTABLISHED:
			data = data + bytes([0x0] * (16 - len(data) % 16))
			packet = WireGuardDataPacket()
			counter = utils.misc.Math.int_to_bytes(entry.NSend)
			if (len(counter) % 8) > 0:
				counter = bytes([0x0] * (8 - len(counter) % 8)) + counter
			packet.counter(counter)
			packet.receiver(entry.R)			
			packet.data(crypto.aead.AEAD(entry.TSend, counter, data, entry.Ci))

def wg_loop():
	while True:
		data, address = wg_socket.recvfrom(MTU)
		packet = WireGuardPacket(data)
		if packet.type() == p.WIREGUARD_INITIATOR_TYPE:
			packet = WireGuardInitiatorPacket(data)
			h = crypto.digest.Digest()
			Ci = h.digest(crypto.constants.CONSTRUCTION)
			h = crypto.digest.Digest()
			Hi = h.digest(Ci + crypto.constants.IDENTIFIER)
			h = crypto.digest.Digest()
			Hi = h.digest(Hi + Spub)
			Epub = packet.ephimeral()
			Ci = crypto.digest.KDF.kdf1(Ci, Epub)
			ri = packet.sender()
			h = crypto.digest.Digest()
			Hi = h.digest(Hi + Epub)
			(Ci, k) = crypto.digest.KDF.kdf2(Ci, Spriv.exchange(crypto.curve25519.X25519PublicKey.from_public_bytes(Epub)))
			aead = crypto.aead.AEAD(k, bytes([0x0] * 8))
			Sipub = aead.decrypt(packet.static(), Hi)
			entry = table.get_by_key(Sipub)
			if not entry:
				continue
			h = crypto.digest.Digest()
			Hi = h.digest(Hi + packet.static())
			(Ci, k) = crypto.digest.KDF.kdf2(Ci, Spriv.exchange(crypto.curve25519.X25519PublicKey.from_public_bytes(Sipub)))
			aead = crypto.aead.AEAD(k, bytes([0x0] * 8))			
			timestamp = aead.encrypt(packet.timestamp(), Hi)
			h = crypto.digest.Digest()
			Hi = h.digest(Hi + timestamp)
			
			# Create response here...
			Cr = Ci
			Hr = Hi

			Erpriv = crypto.curve25519.X25519PrivateKey.from_private_bytes(os.urandom(32))
			Erpub = Erpriv.public_key()
			entry.Epub = Erpub
			entry.Epriv = Erpriv
			Cr = crypto.digest.KDF.kdf1(Cr, Erpub)
			packet = WireGuardResponderPacket()
			packet.ephimeral(Epub)
			ii = os.urandom(4)
			packet.sender(ii)
			packet.receiver(ri)
			h = crypto.digest.Digest()
			Hr = h.digest(Hr + packet.ephimeral())
			Cr = crypto.digest.KDF.kdf1(Cr, Erpriv.exchange(crypto.curve25519.X25519PublicKey.from_public_bytes(Epub)))
			Cr = crypto.digest.KDF.kdf1(Cr, Erpriv.exchange(crypto.curve25519.X25519PublicKey.from_public_bytes(Sipub)))
			Q = bytes([0x0] * 4)
			(Cr, tau, k) = crypto.digest.KDF.kdf3(Cr, Q)
			h = crypto.digest.Digest()
			Hr = h.digest(Hr + tau)
			aead = crypto.aead.AEAD(k, bytes([0x0] * 8))			
			packet.empty(aead.encrypt(crypto.constants.EMPTY, Hr))
			h = crypto.digest.Digest()
			Hr = h.digest(Hr + packet.empty())

			buffer = packet.buffer[:p.RESPONDER_MSG_ALPHA_OFFSET]
			h = crypto.digest.Digest()
			m = crypto.digest.MACDigest(h.digest(crypto.constants.LABEL_MAC1 + Spub), buffer)
			packet.mac1(m)

			(Trecv, Tsend) = crypto.digest.KDF.kdf2(Cr, crypto.constants.EMPTY)

			wg_socket.sendto(packet.buffer, address)
			entry.state = Statemachine.States.R_SENT
			entry.rekey_timeout = time() + Statemachine.RekeyTimeout
			entry.R = ii
			entry.TSend = Tsend
			entry.TRecv = Trecv

		elif packet.type() == p.WIREGUARD_RESPONDER_TYPE:
			packet = WireGuardResponderPacket(data)
			ir = packet.sender()
			ii = packet.receiver()
			entry = table.get_by_id(ii)
			if not entry:
				continue

			Cr = entry.Ci
			Hr = entry.Hi

			Erpub = packet.ephimeral()
			Cr = crypto.digest.KDF.kdf1(Cr, Epub)
			h = crypto.digest.Digest()
			Hr = h.digest(Hr + packet.ephimeral())
			Eipriv = crypto.curve25519.X25519PrivateKey.from_private_bytes(entry.Epriv)

			Cr = crypto.digest.KDF.kdf1(Cr, Eipriv.exchange(crypto.curve25519.X25519PublicKey.from_public_bytes(Erpub)))
			Cr = crypto.digest.KDF.kdf1(Cr, Spriv.exchange(crypto.curve25519.X25519PublicKey.from_public_bytes(Erpub)))
			Q = bytes([0x0] * 4)
			(Cr, tau, k) = crypto.digest.KDF.kdf3(Cr, Q)
			h = crypto.digest.Digest()
			Hr = h.digest(Hr + tau)
			h = crypto.digest.Digest()
			Hr = h.digest(Hr + packet.empty())

			(Tsend, Trecv) = crypto.digest.KDF.kdf2(Cr, crypto.constants.EMPTY)

			entry.state = Statemachine.States.ESTABLISHED
			entry.rekey_timeout = time() + Statemachine.RekeyTimeout
			entry.R = ir
			entry.TSend = Tsend
			entry.TRecv = Trecv

		elif packet.type() == p.WIREGUARD_TRANSPORT_DATA_TYPE:
			packet = WireGuardDataPacket(data);
			ii = packet.receiver()
			entry = table.get_by_id(ii)
			if not entry:
				continue
			data = packet.data()
			Nsend = utils.misc.Math.bytes_to_int(packet.counter())
			aead = crypto.aead.AEAD(entry.TRecv, packet.counter())
			data = aead.decrypt(data, crypto.constants.EMPTY)
			ipv4 = IPv4Packet(data)
			tun.send(ipv4.get_buffer()[:ipv4.get_total_length()])
		elif packet.type() == p.WIREGUARD_COOKIE_REPLY_TYPE:
			packet = WireGuardCookiePacket(data)
			
			# 1) Send initiator packet

wg_th_loop = threading.Thread(target = wg_loop, args = (), daemon = True);
tun_th_loop = threading.Thread(target = tun_loop, args = (), daemon = True);
config_th_loop = threading.Thread(target = config_loop, args = (), daemon = True);

logging.info("Starting the WireGuard");

wg_th_loop.start();
config_th_loop.start();
tun_th_loop.start();

def maintenance():
	while True:
		logging.debug("Periodic task")
		sleep(5)

maintenance()