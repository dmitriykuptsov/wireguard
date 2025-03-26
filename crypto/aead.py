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

from Crypto.Cipher import ChaCha20_Poly1305


class AEAD():
    def __init__(self, key, counter):
        if len(key) != 32:
            raise ValueError("key must be 32 bytes")
        if len(counter) != 8:
            raise ValueError("counter must be 8 bytes")
        counter = bytes([0x0] * 4) + counter
        self.key = key
        self.counter = counter

    def encrypt(self, data, auth):
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=self.counter)
        cipher.update(auth)
        o = cipher.encrypt_and_digest(data)
        return o[0] + o[1]

    def decrypt(self, data, auth, tag):
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=self.counter)
        cipher.update(auth)
        return cipher.decrypt_and_verify(data, tag)


class xAEAD():
    def __init__(self, key, nonce):
        if len(key) != 32:
            raise ValueError("key must be 32 bytes")
        if len(nonce) != 24:
            raise ValueError("nonce must be 24 bytes")
        self.key = key
        self.nonce = nonce

    def encrypt(self, data, auth):
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=self.counter)
        cipher.update(auth)
        o = cipher.encrypt_and_digest(data)
        return o[0] + o[1]

    def decrypt(self, data, auth, tag):
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=self.counter)
        cipher.update(auth)
        return cipher.decrypt_and_verify(data, tag)

# import os
# key = os.urandom(32)
# counter = os.urandom(8)
# c = AEAD(key, counter)
# data = b'Hello, world!'
# ad = b'Header!'
# (cipher, tag) = c.encrypt_and_digest(data, ad)
# c = AEAD(key, counter)
# data = b'Hello, world!'
# ad = b'Header!'
# print(c.decrypt_and_verify(cipher, ad, tag))
