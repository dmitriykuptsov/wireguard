from base64 import b64decode, b64encode
from utils.misc import Math
from time import time


class CryptoRoutingEntry():

    ip = None
    ip_s = None
    prefix = None
    key = None
    port = None
    I = None
    R = None
    TSend = None
    TRecv = None
    NSend = 0
    NRecv = 0
    Cr = None
    Ci = None
    Hr = None
    Hi = None
    Epriv = None
    Epub = None
    state = None
    timestamp = 0
    rekey_timeout = time()
    rekey_after_timeout = time()
    reject_after_timeout = time()
    cookie = "".encode("UTF-8")
    nonce = "".encode("UTF-8")
    cookie_timeout = 0
    message_sent = 0
    is_initiator = False
    dst = None

    def __init__(self, ip, prefix, key, port, ip_s):
        self.ip_s = ip_s
        self.ip = ip
        self.prefix = prefix
        self.key = key
        self.port = port

    def match_by_ip(self, dst):
        dst = dst & self.prefix
        if dst & self.ip == self.ip & self.prefix:
            return True
        return False

    def match_by_key(self, key):
        if key == self.key:
            return True
        return False

    def match_by_id(self, id):
        if id == self.I:
            return True
        return False

    def __str__(self):
        prefix = Math.int_to_bytes(self.prefix)
        prefix = str(prefix[0]) + "." + str(prefix[1]) + \
            "." + str(prefix[2]) + "." + str(prefix[3])
        ip = Math.int_to_bytes(self.ip)
        ip = str(ip[0]) + "." + str(ip[1]) + "." + \
            str(ip[2]) + "." + str(ip[3])
        return b64encode(self.key).decode("ASCII") + " " + ip + " " + prefix + " " + str(self.port) + " " + self.ip_s


def recmp(left, right):
    if left.ip < right.ip:
        return -1
    if left.ip == right.ip:
        return 0
    return 1


class RoutingTable():
    def __init__(self):
        self.table = []

    def add(self, entry):
        self.table.append(entry)

    def delete(self, entry):
        for e in self.table:
            if e.key == entry.key:
                self.table.remove(e)
                break

    def get_by_ip(self, ip):
        for e in self.table:
            if e.match_by_ip(ip):
                return e
        return None

    def get_by_key(self, key):
        for e in self.table:
            if e.match_by_key(key):
                return e
        return None

    def get_by_id(self, id):
        for e in self.table:
            if e.match_by_id(id):
                return e
        return None
