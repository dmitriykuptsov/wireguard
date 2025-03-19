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

from Crypto.Hash import HMAC, BLAKE2s

class HMACDigest():
	B_LENGTH = 64;
	def __init__(self, key = None):
		self.key = key;
	
	@staticmethod
	def xor(one, two):
		return bytes(a ^ b for (a, b) in zip(one, two))

	def digest(self, data):
		if len(self.key) > self.B_LENGTH:
			h = BLAKE2s.new(digest_bits=256)
			h.update(self.key)
			self.key = h.digest()
			self.key = self.key + bytes([0] * (self.B_LENGTH - len(self.key)))
		elif len(self.key) < self.B_LENGTH:
			self.key = self.key + bytes([0] * (self.B_LENGTH - len(self.key)))
		opad = bytes([0x5c] * self.B_LENGTH)
		ipad = bytes([0x36] * self.B_LENGTH)
		p1 = HMACDigest.xor(self.key, opad)
		h = BLAKE2s.new(digest_bits=256)
		h.update(HMACDigest.xor(self.key, ipad) + data)
		p2 = h.digest()
		h = BLAKE2s.new(digest_bits=256)
		h.update(p1 + p2)
		return h.digest()

#from binascii import hexlify
#h = HMACDigest(b'testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest')
#print(hexlify(h.digest(b'testtesttesttesttesttesttesttest')));

#hmac = HMAC.new(b'testtesttesttesttesttesttesttest', digestmod=SHA256);
#hmac.update(b'testtesttesttesttesttesttesttest');
#print(hexlify(hmac.digest()));

class Digest():
	def __init__(self):
		pass
	def digest(self, data):
		h = BLAKE2s.new(digest_bits=256)
		h.update(data)
		return h.digest()

