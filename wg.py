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
from binascii import hexlify

# Configure logging to console and file
logging.basicConfig(
	level=logging.CRITICAL,
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
wg_socket.bind(('', int(config.get(Config.PORT))))
MTU = 1200

tun = TunTunnel(pattern = "wg0");
tun.set_ipv4(config.get(Config.LOCAL))
tun.set_mtu(MTU);

# Read this from file instead
Spriv = crypto.curve25519.X25519PrivateKey.from_private_bytes(b64decode(config.get(Config.KEY)))
Spub = Spriv.public_key()

R = os.urandom(32)
R_reg_interval = time()

under_load = False

UNDER_LOAD_THRESHOLD = 5
MEASUREMENT_THRESHOLD = 120 # 2 minutes
requests_per_second = 0
last_minute = time()

def tun_loop():
	while True:
		data = tun.recv(MTU);
		#logging.debug("Got packet on wg0...")
		ip = IPv4Packet(data);
		dst = utils.misc.Math.bytes_to_int(ip.get_destination_address());
		entry = table.get_by_ip(dst)
		if not entry:
			logging.debug("Entry is missing....")
			continue
		try:
			if entry.state != Statemachine.States.ESTABLISHED and entry.rekey_timeout <= time():
				logging.debug("State is missing... Running key exchange....")
				entry.is_initiator = True
				Srpub = entry.key
				h = crypto.digest.Digest()
				Ci = h.digest(crypto.constants.CONSTRUCTION)
				h = crypto.digest.Digest()
				Hi = h.digest(Ci + crypto.constants.IDENTIFIER)
				logging.debug("(1) Hi HEX %s" % hexlify(Hi))
				h = crypto.digest.Digest()
				Hi = h.digest(Hi + Srpub)
				logging.debug("Peer's public key %s" % hexlify(Srpub))
				Epriv = crypto.curve25519.X25519PrivateKey.from_private_bytes(os.urandom(32))
				Epub = Epriv.public_key()
				logging.debug("Ci HEX %s" % hexlify(Ci))
				logging.debug("Epub %s" % hexlify(Epub))
				Ci = crypto.digest.KDF.kdf1(Ci, Epub)
				logging.debug("Ci HEX %s" % hexlify(Ci))
				packet = WireGuardInitiatorPacket()
				ii = os.urandom(4)
				packet.sender(ii)
				packet.ephimeral(Epub)
				logging.debug("Getting own EPUB %s" % hexlify(packet.ephimeral()))
				h = crypto.digest.Digest()
				Hi = h.digest(Hi + packet.ephimeral())
				logging.debug("Hi HEX %s" % hexlify(Hi))
				(Ci, k) = crypto.digest.KDF.kdf2(Ci, Epriv.exchange(crypto.curve25519.X25519PublicKey.from_public_bytes(Srpub)))
				aead = crypto.aead.AEAD(k, bytes([0x0] * 8))
				packet.static(aead.encrypt(Spub, Hi))
				aead = crypto.aead.AEAD(k, bytes([0x0] * 8))
				logging.debug("The public key to be transmitted is .... %s" % (b64encode(aead.decrypt(packet.static()[:-16], Hi, packet.static()[-16:])).decode("ASCII")))
				h = crypto.digest.Digest()
				Hi = h.digest(Hi + packet.static())
				(Ci, k) = crypto.digest.KDF.kdf2(Ci, Spriv.exchange(crypto.curve25519.X25519PublicKey.from_public_bytes(Srpub)))
				aead = crypto.aead.AEAD(k, bytes([0x0] * 8))
				packet.timestamp(aead.encrypt(utils.misc.Math.tai64n(), Hi))
				logging.debug("TIMESTAMPT %s" % (hexlify(packet.timestamp())))
				logging.debug("Hi %s" % (hexlify(Hi)))
				h = crypto.digest.Digest()
				Hi = h.digest(Hi + packet.timestamp())

				entry.state = Statemachine.States.I_SENT
				entry.rekey_timeout = time() + Statemachine.RekeyTimeout
				entry.I = ii
				entry.Ci = Ci
				entry.Hi = Hi
				entry.Epub = Epub
				entry.Epriv = Epriv.private_bytes()

				buffer = packet.buffer[:p.INITIATOR_MSG_ALPHA_OFFSET]
				h = crypto.digest.Digest()
				m = crypto.digest.MACDigest(h.digest(crypto.constants.LABEL_MAC1 + Srpub))
				packet.mac1(m.digest(buffer))
				
				if entry.cookie == crypto.constants.EMPTY or entry.cookie_timeout - time() > 120:
					packet.mac2(bytes([0x0] * 16))
				else:
					m = crypto.digest.MACDigest(entry.cookie)
					buffer = packet.buffer[:p.INITIATOR_MSG_BETA_OFFSET]
					packet.mac2(m.digest(buffer))
				
				wg_socket.sendto(packet.buffer, (entry.ip_s, entry.port))

				logging.debug("Sent packet.... to %s %s" % (entry.ip_s, str(entry.port)))
			elif entry.state == Statemachine.States.ESTABLISHED:
				data = data + bytes([0x0] * (16 - len(data) % 16))
				packet = WireGuardDataPacket()
				counter = utils.misc.Math.int_to_bytes(entry.NSend)
				entry.NSend += 1
				entry.rekey_after_timeout = time()
				if (len(counter) % 8) > 0:
					counter = bytes([0x0] * (8 - len(counter) % 8)) + counter
				packet.counter(counter)
				packet.receiver(entry.R)
				aead = crypto.aead.AEAD(entry.TSend, counter)
				packet.data(aead.encrypt(data, crypto.constants.EMPTY))
				wg_socket.sendto(packet.buffer, (entry.ip_s, entry.port))
				entry.message_sent += 1
				logging.debug("Sent packet.... to %s %s" % (entry.ip_s, str(entry.port)))
		except Exception as e:
			logging.critical(e)

def wg_loop():
	
	global R
	global under_load
	global requests_per_second
	global last_minute
	global MEASUREMENT_THRESHOLD
	global UNDER_LOAD_THRESHOLD

	while True:
		data, (ip, port) = wg_socket.recvfrom(2*MTU)
		packet = WireGuardPacket(data)
		try:
			if packet.type() == p.WIREGUARD_INITIATOR_TYPE:
				requests_per_second += 1
				if time() - last_minute >= MEASUREMENT_THRESHOLD:
					if requests_per_second / MEASUREMENT_THRESHOLD > UNDER_LOAD_THRESHOLD:
						under_load = True
					else:
						under_load = False
					last_minute = time()
					requests_per_second = 0

				packet = WireGuardInitiatorPacket(data)
				mac1 = packet.mac1()

				buffer = packet.buffer[:p.INITIATOR_MSG_ALPHA_OFFSET]
				h = crypto.digest.Digest()
				m = crypto.digest.MACDigest(h.digest(crypto.constants.LABEL_MAC1 + Spub))

				if mac1 != m.digest(buffer):
					logging.debug("Invalid MAC 1 value.... dropping packet...")
					continue

				entry.is_initiator = False

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
				Sipub = aead.decrypt(packet.static()[:-16], Hi, packet.static()[-16:])
				entry = table.get_by_key(Sipub)

				if not entry:
					logging.debug("Missing entry.....")
					continue
				if under_load:
					ii = packet.sender()
					m = crypto.digest.MACDigest(R)
					tau = m.digest(ip.encode("ASCII") + utils.misc.Math.int_to_bytes(int(port)))
					packet = WireGuardCookiePacket()
					packet.nonce(os.urandom(24))
					packet.receiver(ii)
					d = crypto.digest.Digest()
					xaead = crypto.aead.xAEAD(d.digest(crypto.constants.LABEL_COOKIE + Spub), packet.nonce())
					packet.cookie(xaead.encrypt(tau, mac1))
					wg_socket.sendto(packet.buffer, (ip, int(port)))
					entry.cookie = packet.cookie()
					entry.nonce = packet.nonce()
					entry.cookie_timeout = time()
					continue
				if time() - entry.cookie_timeout < 120:
					m = crypto.digest.MACDigest(entry.cookie)
					buffer = packet.buffer[:p.INITIATOR_MSG_BETA_OFFSET]
					if packet.mac2() != m.digest(buffer):
						logging.debug("Invalid MAC 2... dropping packet")
						continue
					m = crypto.digest.MACDigest(R)
					tau = m.digest(ip.encode("ASCII") + utils.misc.Math.int_to_bytes(int(port)))
					d = crypto.digest.Digest()
					xaead = crypto.aead.xAEAD(d.digest(crypto.constants.LABEL_COOKIE + Spub), entry.nonce)
					cookie = xaead.encrypt(tau, mac1)
					if cookie != entry.cookie:
						logging.debug("Invalid cookie... dropping packet")
						continue
					entry.cookie = crypto.constants.EMPTY
					entry.nonce = crypto.constants.EMPTY
				h = crypto.digest.Digest()
				Hi = h.digest(Hi + packet.static())
				(Ci, k) = crypto.digest.KDF.kdf2(Ci, Spriv.exchange(crypto.curve25519.X25519PublicKey.from_public_bytes(Sipub)))
				aead = crypto.aead.AEAD(k, bytes([0x0] * 8))			
				timestamp = aead.decrypt(packet.timestamp()[:-16], Hi, packet.timestamp()[-16:])
				if entry.timestamp > utils.misc.Math.bytes_to_int(timestamp[:8]):
					logging.debug("Timestamp is in the future...")
					logging.debug(utils.misc.Math.bytes_to_int(timestamp[:8]))
					continue
				entry.timestamp = utils.misc.Math.bytes_to_int(timestamp[:8])
				h = crypto.digest.Digest()
				Hi = h.digest(Hi + packet.timestamp())
				
				# Create response here...
				Cr = Ci
				Hr = Hi

				Erpriv = crypto.curve25519.X25519PrivateKey.from_private_bytes(os.urandom(32))
				Erpub = Erpriv.public_key()
				entry.Epub = Erpub
				entry.Epriv = Erpriv

				Cr = crypto.digest.KDF.kdf1(Cr, Erpub)
				packet = WireGuardResponderPacket()
				packet.ephimeral(Erpub)
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
				m = crypto.digest.MACDigest(h.digest(crypto.constants.LABEL_MAC1 + Sipub))
				packet.mac1(m.digest(buffer))

				if entry.cookie == crypto.constants.EMPTY or entry.cookie_timeout - time() > 120:
					packet.mac2(bytes([0x0] * 16))
				else:
					m = crypto.digest.MACDigest(entry.cookie)
					buffer = packet.buffer[:p.RESPONDER_MSG_BETA_OFFSET]
					packet.mac2(m.digest(buffer))

				(Trecv, Tsend) = crypto.digest.KDF.kdf2(Cr, crypto.constants.EMPTY)

				logging.debug("Sent reply to initiator packet.... to %s %s" % (entry.ip_s, str(entry.port)))

				wg_socket.sendto(packet.buffer, (entry.ip_s, int(entry.port)))
				entry.state = Statemachine.States.ESTABLISHED
				entry.rekey_timeout = time() + Statemachine.RekeyTimeout
				entry.R = ii
				entry.I = ri
				entry.TSend = Tsend
				entry.TRecv = Trecv
				entry.NSend = 0
				entry.NRecv = 0

				print("Tsend %s" % (hexlify(Tsend)))
				print("Trecv %s" % (hexlify(Trecv)))

			elif packet.type() == p.WIREGUARD_RESPONDER_TYPE:
				packet = WireGuardResponderPacket(data)
				ii = packet.sender()
				ir = packet.receiver()

				buffer = packet.buffer[:p.RESPONDER_MSG_ALPHA_OFFSET]
				h = crypto.digest.Digest()
				m = crypto.digest.MACDigest(h.digest(crypto.constants.LABEL_MAC1 + Spub))
				if packet.mac1() != m.digest(buffer):
					logging.debug("Invalid MAC 1 value.... dropping packet...")
					continue

				entry = table.get_by_id(ir)

				if not entry:
					continue

				Cr = entry.Ci
				Hr = entry.Hi

				Erpub = packet.ephimeral()
				Cr = crypto.digest.KDF.kdf1(Cr, Erpub)
				h = crypto.digest.Digest()
				Hr = h.digest(Hr + Erpub)
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

				print("Tsend %s" % (hexlify(Tsend)))
				print("Trecv %s" % (hexlify(Trecv)))

				entry.state = Statemachine.States.ESTABLISHED
				entry.rekey_timeout = time() + Statemachine.RekeyTimeout
				entry.R = ir
				entry.I = ii
				entry.TSend = Tsend
				entry.TRecv = Trecv

				entry.NSend = 0
				entry.NRecv = 0

			elif packet.type() == p.WIREGUARD_TRANSPORT_DATA_TYPE:
				packet = WireGuardDataPacket(data);
				ri = packet.receiver()
				entry = table.get_by_id(ri)
				if not entry:
					continue
				Nsend = utils.misc.Math.bytes_to_int(packet.counter())
				if not (Nsend > entry.NRecv - Statemachine.SequenceWindow and Nsend < entry.NRecv + Statemachine.SequenceWindow):
					logging.debug("Replay packet")
					continue
				aead = crypto.aead.AEAD(entry.TRecv, packet.counter())
				try:
					data = aead.decrypt(packet.data()[:-16], crypto.constants.EMPTY, packet.data()[-16:])
				except Exception as e:
					logging.critical(e)
					continue
				ipv4 = IPv4Packet(data)
				entry.reject_after_timeout = time()
				entry.NRecv = Nsend
				tun.send(ipv4.get_buffer()[:ipv4.get_total_length() + 4])
				#logging.debug(hexlify(ipv4.get_buffer()))
			elif packet.type() == p.WIREGUARD_COOKIE_REPLY_TYPE:
				packet = WireGuardCookiePacket(data)
				ri = packet.receiver()
				entry = table.get_by_id(ri)
				if not entry:
					continue
				entry.cookie = packet.cookie()
				entry.cookie_timeout = time()
		except Exception as e:
			logging.critical(e)

wg_th_loop = threading.Thread(target = wg_loop, args = (), daemon = True);
tun_th_loop = threading.Thread(target = tun_loop, args = (), daemon = True);
config_th_loop = threading.Thread(target = config_loop, args = (), daemon = True);

logging.info("Starting the WireGuard");

wg_th_loop.start();
config_th_loop.start();
tun_th_loop.start();

def maintenance():
	global R_reg_interval
	global Spub
	global Spriv
	global R
	while True:
		logging.debug("Periodic task")
		if R_reg_interval < time():
			R_reg_interval = time() + 120
			R = os.urandom(32)
		for entry in table.table:
			if not entry.is_initiator:
				continue
			if time() - entry.rekey_after_timeout < Statemachine.RekeyAfterTime and \
				time() - entry.reject_after_timeout < (Statemachine.RejectAfterTime - Statemachine.KeepaliveTimeout - Statemachine.RekeyTimeout) and \
				entry.message_sent <= Statemachine.RekeyAfterMessages:
				continue
			if entry.cookie != crypto.constants.EMPTY and entry.cookie_timeout + Statemachine.RekeyTimeout > time():
				continue
			entry.is_initiator = True
			entry.message_sent = 0
			logging.debug("State is missing (periodic task)... Running key exchange....")
			Srpub = entry.key
			h = crypto.digest.Digest()
			Ci = h.digest(crypto.constants.CONSTRUCTION)
			h = crypto.digest.Digest()
			Hi = h.digest(Ci + crypto.constants.IDENTIFIER)
			logging.debug("(1) Hi HEX %s" % hexlify(Hi))
			h = crypto.digest.Digest()
			Hi = h.digest(Hi + Srpub)
			logging.debug("Peer's public key %s" % hexlify(Srpub))
			Epriv = crypto.curve25519.X25519PrivateKey.from_private_bytes(os.urandom(32))
			Epub = Epriv.public_key()
			logging.debug("Ci HEX %s" % hexlify(Ci))
			logging.debug("Epub %s" % hexlify(Epub))
			Ci = crypto.digest.KDF.kdf1(Ci, Epub)
			logging.debug("Ci HEX %s" % hexlify(Ci))
			packet = WireGuardInitiatorPacket()
			ii = os.urandom(4)
			packet.sender(ii)
			packet.ephimeral(Epub)
			logging.debug("Getting own EPUB %s" % hexlify(packet.ephimeral()))
			h = crypto.digest.Digest()
			Hi = h.digest(Hi + packet.ephimeral())
			logging.debug("Hi HEX %s" % hexlify(Hi))
			(Ci, k) = crypto.digest.KDF.kdf2(Ci, Epriv.exchange(crypto.curve25519.X25519PublicKey.from_public_bytes(Srpub)))
			aead = crypto.aead.AEAD(k, bytes([0x0] * 8))
			packet.static(aead.encrypt(Spub, Hi))
			aead = crypto.aead.AEAD(k, bytes([0x0] * 8))
			logging.debug("The public key to be transmitted is .... %s" % (b64encode(aead.decrypt(packet.static()[:-16], Hi, packet.static()[-16:])).decode("ASCII")))
			h = crypto.digest.Digest()
			Hi = h.digest(Hi + packet.static())
			(Ci, k) = crypto.digest.KDF.kdf2(Ci, Spriv.exchange(crypto.curve25519.X25519PublicKey.from_public_bytes(Srpub)))
			aead = crypto.aead.AEAD(k, bytes([0x0] * 8))
			packet.timestamp(aead.encrypt(utils.misc.Math.tai64n(), Hi))
			logging.debug("TIMESTAMPT %s" % (hexlify(packet.timestamp())))
			logging.debug("Hi %s" % (hexlify(Hi)))
			h = crypto.digest.Digest()
			Hi = h.digest(Hi + packet.timestamp())
			entry.state = Statemachine.States.I_SENT
			entry.rekey_timeout = time() + Statemachine.RekeyTimeout
			entry.I = ii
			entry.Ci = Ci
			entry.Hi = Hi
			entry.Epub = Epub
			entry.Epriv = Epriv.private_bytes()
			buffer = packet.buffer[:p.INITIATOR_MSG_ALPHA_OFFSET]
			h = crypto.digest.Digest()
			m = crypto.digest.MACDigest(h.digest(crypto.constants.LABEL_MAC1 + Srpub))
			packet.mac1(m.digest(buffer))
			
			if entry.cookie == crypto.constants.EMPTY or entry.cookie_timeout - time() > 120:
				packet.mac2(bytes([0x0] * 16))
			else:
				m = crypto.digest.MACDigest(entry.cookie)
				buffer = packet.buffer[:p.RESPONDER_MSG_BETA_OFFSET]
				packet.mac2(m.digest(buffer))
			entry.cookie = crypto.constants.EMPTY
			entry.cookie_timeout = 0

			logging.debug("Epub %s" % hexlify(packet.ephimeral()))
			wg_socket.sendto(packet.buffer, (entry.ip_s, entry.port))
			logging.debug("Sent packet.... to %s %s" % (entry.ip_s, str(entry.port)))
		sleep(5)

maintenance()
