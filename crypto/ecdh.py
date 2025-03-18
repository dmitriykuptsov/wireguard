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

class ECDHCurve25519():
	def __init__(self):
		self.private_key_size = 32;
		self.modulus = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
		self.group_order = 2^252 + 0x14def9dea2f79cd65812631a5cf5d3ed;
		self.b = 0x01;
		self.gx = 0x9;
		self.gy = 0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9;
		self.a = 0x76d06;
		self.h = 0x08;
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
		return misc.Math.double_and_add(public_key, self.private_key, self.a, self.b, self.modulus).x;

	def encode_public_key(self):
		x = misc.Math.int_to_bytes(self.public_key.get_x());
		if len(x) != self.component_bit_length:
			x = bytearray([0] * (self.component_bit_length - len(x))) + x;
		y = misc.Math.int_to_bytes(self.public_key.get_y());
		if len(y) != self.component_bit_length:
			y = bytearray([0] * (self.component_bit_length - len(y))) + y;
		return x + y;

	def compress_point(self, Q):
		return (Q.get_x() | (1 << 255) if Q.get_y() % 0x2 else Q.get_x())
	
	def decompress_point(self, Q):
		is_odd = (Q.get_x() >> 255) & 1
		x = Q.get_x() & ((1 << 255) - 1)
		rhs = (x**3 + self.a*x + self.b) % self.p
		y = pow(rhs, (self.p+1)//4, self.p)
		if (y % 2) != is_odd:
			y = self.p - y
		return misc.ECPoint(x, y)