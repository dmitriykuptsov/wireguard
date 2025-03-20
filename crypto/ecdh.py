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

#https://ru.qwe.wiki/wiki/Elliptic_curve

import sys
import os
sys.path.append(os.getcwd())

import utils
#from utils.misc import misc.Math, misc.ECPoint
from utils import misc
from binascii import unhexlify
from os import urandom
import crypto

class ECDHNIST256():
	def __init__(self):
		self.private_key_size = 32;
		self.modulus = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
		self.group_order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;
		self.b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b;
		self.gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296;
		self.gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5;
		self.a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc;
		self.h = 0x1;
		self.G = misc.ECPoint(self.gx, self.gy);
		self.component_bit_length = 32;

	def get_component_length(self):
		return self.component_bit_length;

	def set_private_key(self, key):
		self.private_key = key;

	def generate_private_key(self):
		self.private_key = misc.Math.bytes_to_int(bytearray(urandom(self.private_key_size)));

	def generate_public_key(self):
		self.public_key = misc.Math.double_and_add(self.G, self.private_key, self.a, self.b, self.modulus);
		return self.public_key;

	def compute_shared_secret(self, public_key):
		return misc.Math.double_and_add(public_key, self.private_key, self.a, self.b, self.modulus);

	def encode_public_key(self):
		x = misc.Math.int_to_bytes(self.public_key.get_x());
		if len(x) != self.component_bit_length:
			x = bytearray([0] * (self.component_bit_length - len(x))) + x;
		y = misc.Math.int_to_bytes(self.public_key.get_y());
		if len(y) != self.component_bit_length:
			y = bytearray([0] * (self.component_bit_length - len(y))) + y;
		return x + y;

	def compress_point(self, Q):
		#return (Q.get_x() | (1 << 255) if Q.get_y() % 0x2 else Q.get_x())
		return (Q.get_x(), Q.get_y() % 0x2)
	
	def decompress_point(self, x, is_odd):
		y = misc.Math.modular_sqrt(x**3 + self.a*x + self.b, self.modulus)
		if bool(y & 0x1) == bool(is_odd):
			return misc.ECPoint(x, y)
		return misc.ECPoint(x, self.modulus - y)

ec = ECDHNIST256()
ec.set_private_key(0xC88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433)
print("Public Key:")
Q = ec.generate_public_key()
print(Q)
print("--------------------------------")
ec2 = ECDHNIST256()
ec2.set_private_key(0xC6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53)
print(ec2.generate_public_key())
print(ec.compute_shared_secret(ec2.generate_public_key()))
#ec.generate_private_key()
#public = ec.generate_public_key()
#print(public)
#print("public")
#Q = ec.generate_public_key()
(x, is_odd) = ec.compress_point(Q)
dQ = ec.decompress_point(x, is_odd)
print("Decompressed:")
print(dQ)
print("--------------------------------")