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

from time import sleep
from network.pytun import TunTunnel
import sys
import os
sys.path.append("../")


PSEUDO_HEADER_SIZE = 0x4


class Tun():
    """
    Initializes the tun device
    """

    def __init__(self, address="10.0.0.2", mtu=1500, name="wg0"):
        self.name = name
        self.tun = TunTunnel(pattern=name)
        self.tun.set_ipv4(address)
        self.tun.set_mtu(mtu)

    def set_address(self, address):
        self.tun.set_ipv4(address)
    """
	Reads data from device
	"""

    def read(self, nbytes=1500):
        # return self.tun.recv(nbytes + PSEUDO_HEADER_SIZE);
        return self.tun.recv(nbytes)
    """
	Writes buffer to device
	"""

    def write(self, buf):
        return self.tun.send(buf)
    """
	Closes TUN interface
	"""

    def close(self):
        self.tun.down()
