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
from states import Statemachine
# Cryptography
import crypto
# OS stuff
import os
# Misc stuff
import utils.misc

# Configure logging to console and file
logging.basicConfig(
	level=logging.DEBUG,
	format="%(asctime)s [%(levelname)s] %(message)s",
	handlers=[
		logging.FileHandler("hip.log"),
		logging.StreamHandler(sys.stdout)
	]
);

def config_loop():
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind(("127.0.0.1", 10000))
	s.listen(5)
	while True:
		reading = True
		conn, addr = s.accept()
		while reading:
			command = conn.recv(2000);
			command=command.decode("ASCII").strip()
			if command == "status":
				conn.send("Status: \n".encode("ASCII"))
			elif command.strip() == "exit" or command.strip() == "":
				conn.close();
				reading = False;
		s.close()

wg_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
wg_socket.bind(('', 12000))
MTU = 1460

tun = TunTunnel(pattern = "wg0");
#tun.set_ipv4(address);
tun.set_mtu(MTU);

sa_storage = Statemachine.Storage()
sm_storage = Statemachine.Storage()

# Read this from file instead
Spriv = crypto.curve25519.X25519PrivateKey.from_private_bytes(os.random(32))
Spub = Spriv.public_key()

def tun_loop():
	while True:
		data = tun.recv();
		ip = IPv4Packet(data)
		dst = ip.get_destination_address()
		# 1) Check the destination
		# 2) If the association exists then send encrypted packet to the destination
		# 3) If no destination exists, initiate the 
		sa = sa_storage.get_record(hash(dst))
		if not sa:
			h = crypto.digest.Digest()
			Ci = h.digest(crypto.constants.CONSTRUCTION)
			h = crypto.digest.Digest()
			Hi = h.digest(Ci + crypto.constants.IDENTIFIER)
			h = crypto.digest.Digest()
			Hi = h.digest(Hi + Spub)
			Epriv = crypto.curve25519.X25519PrivateKey.from_private_bytes(os.random(32))
			Epub = Spriv.public_key()
			Ci = crypto.digest.KDF.kdf1(Ci, Epub)
			packet = WireGuardInitiatorPacket()
			packet.ephimeral(Epub)
			h = crypto.digest.Digest()
			Hi = h.digest(Hi + packet.ephimeral())
			(Ci, k) = crypto.digest.KDF.kdf2(Ci, Spriv.exchange(Spub))
			aead = crypto.aead.AEAD(k, 0)
			enc_static = aead.encrypt(Spub, Hi)
			packet.static(enc_static)
			h = crypto.digest.Digest()
			Hi = h.digest(Hi + packet.static())
			(Ci, k) = crypto.digest.KDF.kdf2(Ci, Spriv.exchange(Spub))
			aead = crypto.aead.AEAD(k, 0)
			packet.timestamp(aead.encrypt(utils.misc.Math.tai64n(), Hi))
			h = crypto.digest.Digest()
			Hi = h.digest(Hi + packet.timestamp())
			sm = sm_storage.get_record(hash(dst))
			sm.set_state(Statemachine.States.I_SENT)
			# Send initiator packet to the destination
		else:
			pass

def wg_loop():
	while True:
		data, address = wg_socket.recvfrom(MTU)
		packet = WireGuardPacket(data)
		if packet.type() == p.WIREGUARD_INITIATOR_TYPE:
			packet = WireGuardInitiatorPacket(data)
		elif packet.type() == p.WIREGUARD_RESPONDER_TYPE:
			packet = WireGuardResponderPacket(data)
		elif packet.type() == p.WIREGUARD_TRANSPORT_DATA_TYPE:
			packet = WireGuardDataPacket(data);
			data = packet.data()
			# 1) Verify the packet, decrypt and send into wg0
			tun.send(data)
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