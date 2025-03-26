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

from time import time
from os import urandom
import logging
from binascii import hexlify
from math import log, ceil, floor
import sys
import os
sys.path.append(os.getcwd())


# print(sys.modules);


class ECPoint():
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __str__(self):
        return hex(self.x) + ", " + hex(self.y)

    def get_x(self):
        return self.x

    def get_y(self):
        return self.y

    def add(self, P, a, b, modulus):
        if isinstance(self, ECPointInf) and isinstance(P, ECPointInf):
            return ECPointInf()
        elif isinstance(self, ECPointInf):
            return ECPoint(P.get_x(), P.get_y())
        elif isinstance(P, ECPointInf):
            return ECPoint(self.get_x(), self.get_y())
        if P.get_x() == self.x and P.get_y() == self.y:
            y1 = self.y
            x1 = self.x
            t = Math.mul_inverse((2*y1) % modulus, modulus)
            beta = ((3*x1*x1 + a) * t) % modulus
            x3 = (beta*beta - 2*x1) % modulus
            y3 = (beta * (x1-x3) - y1) % modulus
            return ECPoint(x3, y3)
        elif P.get_x() == self.x and P.get_y() == -self.y:
            return ECPointInf()
        elif P.get_x() != self.x or P.get_y() != self.y:
            y1 = self.y
            x1 = self.x
            y2 = P.get_y()
            x2 = P.get_x()
            t1 = Math.mul_inverse(x2 - x1, modulus)
            beta = ((y2 - y1) * t1) % modulus
            x3 = (beta*beta - x1 - x2) % modulus
            y3 = (beta * (x1-x3) - y1) % modulus
            return ECPoint(x3, y3)


class ECPointInf(ECPoint):
    def __init__(self):
        self.x = 0
        self.y = 0

    def get_x(self):
        return self.x

    def get_y(self):
        return self.y

    def add(self, P, a, b, modulus):
        if isinstance(P, ECPointInf):
            return ECPointInf()
        return ECPoint(P.get_x(), P.get_y())


class Math():

    @staticmethod
    def int_to_bytes(number):
        if number == 0:
            return bytearray([0x0])
        length = int(ceil(Math.num_bits(number) / 8))
        byte_array = []
        for i in range(length - 1, -1, -1):
            byte_array.append((number >> (i*8)) & 0xFF)
        # byte_array.reverse();
        return bytearray(byte_array)

    @staticmethod
    def bytes_to_int(bytes):
        result = 0
        for i in range(len(bytes) - 1, -1, -1):
            result += bytes[(len(bytes) - 1) - i] << (8*i)
        return result

    @staticmethod
    def num_bits(n):
        return floor(log(n, 2)) + 1

    @staticmethod
    def to_bit_array(n, reverse=True):
        bitarray = []
        while n > 0:
            r = n & 0x1
            n = n >> 1
            bitarray.append(r)
        if reverse:
            bitarray.reverse()
        return bitarray

    @staticmethod
    def square_and_multiply(base, power, modulus):
        bits = Math.to_bit_array(power, False)
        result = base
        for i in range(len(bits) - 1, 0, -1):
            result = (result * result) % modulus
            if bits[i - 1] == 1:
                result = (result * base) % modulus
        return result
        # 5 = 1*2^2 + 0*2^1 + 1*2^0
        #   = (1*2+0)*2 + 1
        #   = ((x^1)^2*x^0)^2*x^1
        # r = ((x^2)*1)^2*x
        # 4 = 1*2^2 + 0*2^0 + 1*2^0
        # r = ((x^2)*1)^2*1

    @staticmethod
    def double_and_add(G, k, a, b, modulus):
        bits = Math.to_bit_array(k, False)
        P = ECPointInf()
        Q = G
        for i in range(0, len(bits)):
            if bits[i] == 1:
                P = P.add(Q, a, b, modulus)
            Q = Q.add(Q, a, b, modulus)
        # 5 = 101
        # P = G Q = 2G
        # P = G Q = 4G
        # P = 5G Q = 8G
        # 10 = 1010
        # P = 0 Q = 2G
        # P = 2G Q = 4G
        # P = 2G Q = 8G
        # P = 10G Q = 16G
        return P

    @staticmethod
    def compress_point(G):
        return (G.get_x() | (1 << 255) if G.get_y() % 0x2 else G.get_x())

    @staticmethod
    def decompress_point(x, a, b, p):
        is_odd = (x >> 255) & 1
        x = x & ((1 << 255) - 1)
        rhs = (x**3 + a*x + b) % p
        y = pow(rhs, (p+1)//4, p)
        if (y % 2) != is_odd:
            y = p - y
        return ECPoint(x, y)

    @staticmethod
    def mul_inverse(n, modulus):
        a0 = n
        b0 = modulus
        t0 = 0
        t = 1
        s0 = 1
        s = 0
        q = a0 // b0
        r = a0 % b0
        while r > 0:
            temp = t0 - q*t
            t0 = t
            t = temp
            temp = s0 - q*s
            s0 = s
            s = temp
            a0 = b0
            b0 = r
            q = a0 // b0
            r = a0 - q*b0
        r = b0
        return (s % modulus)

    @staticmethod
    def is_coprime(a, b):
        return Math.gcd(a, b) == 1

    @staticmethod
    def gcd(a, b):
        while b != 0:
            t = a % b
            a = b
            b = t
        # a = 7, b = 4
        # a = 4, b = 3
        # a = 3, b = 1
        # a = 1, b = 0
        return a

    @staticmethod
    def modular_sqrt(a, p):

        def legendre_symbol(a, p):
            """ Compute the Legendre symbol a|p using
                    Euler's criterion. p is a prime, a is
                    relatively prime to p (if p divides
                    a, then a|p = 0)
                    Returns 1 if a has a square root modulo
                    p, -1 otherwise.
            """
            ls = pow(a, (p - 1) // 2, p)
            return -1 if ls == p - 1 else ls

        """ Find a quadratic residue (mod p) of 'a'. p
			must be an odd prime.
			Solve the congruence of the form:
				x^2 = a (mod p)
			And returns x. Note that p - x is also a root.
			0 is returned is no square root exists for
			these a and p.
			The Tonelli-Shanks algorithm is used (except
			for some simple cases in which the solution
			is known from an identity). This algorithm
			runs in polynomial time (unless the
			generalized Riemann hypothesis is false).
		"""
        # Simple cases
        #
        if legendre_symbol(a, p) != 1:
            return 0
        elif a == 0:
            return 0
        elif p == 2:
            return p
        elif p % 4 == 3:
            return pow(a, (p + 1) // 4, p)

        # Partition p-1 to s * 2^e for an odd s (i.e.
        # reduce all the powers of 2 from p-1)
        #
        s = p - 1
        e = 0
        while s % 2 == 0:
            s //= 2
            e += 1

        # Find some 'n' with a legendre symbol n|p = -1.
        # Shouldn't take long.
        #
        n = 2
        while legendre_symbol(n, p) != -1:
            n += 1

        # Here be dragons!
        # Read the paper "Square roots from 1; 24, 51,
        # 10 to Dan Shanks" by Ezra Brown for more
        # information
        #

        # x is a guess of the square root that gets better
        # with each iteration.
        # b is the "fudge factor" - by how much we're off
        # with the guess. The invariant x^2 = ab (mod p)
        # is maintained throughout the loop.
        # g is used for successive powers of n to update
        # both a and b
        # r is the exponent - decreases with each update
        #
        x = pow(a, (s + 1) // 2, p)
        b = pow(a, s, p)
        g = pow(n, s, p)
        r = e

        while True:
            t = b
            m = 0
            for m in range(r):
                if t == 1:
                    break
                t = pow(t, 2, p)

            if m == 0:
                return x

            gs = pow(g, 2 ** (r - m - 1), p)
            g = (gs * gs) % p
            x = (x * gs) % p
            b = (b * g) % p
            r = m

    @staticmethod
    def tai64n():
        timestamp = time()
        seconds = int(timestamp)
        nanoseconds = int((timestamp - seconds) * 1000000000)
        seconds_b = Math.int_to_bytes(seconds)
        nanoseconds_b = Math.int_to_bytes(nanoseconds)
        if len(seconds_b) < 8:
            seconds_b = bytes([0] * (8 - len(seconds_b))) + seconds_b
        if len(nanoseconds_b) < 4:
            nanoseconds_b = bytes(
                [0] * (4 - len(nanoseconds_b))) + nanoseconds_b
        return seconds_b + nanoseconds_b
