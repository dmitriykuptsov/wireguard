from base64 import b64decode, b64encode
from utils.misc import Math
class CryptoRoutingEntry():

    ip     = None
    ip_s   = None
    prefix = None
    key    = None
    port   = None
    I      = None
    R      = None
    TSend  = None
    TRecv  = None
    NSend  = 0
    NRecv  = 0
    Cr     = None
    Ci     = None
    Hr     = None
    Hi     = None
    Epriv  = None
    Epub   = None
    state  = None
    rekey_timeout = 0
    cookie = "".encode("UTF-8")
    cookie_timeout = 0

    def __init__(self, ip_s, ip, prefix, key, port):
        self.ip_s = ip_s
        self.ip = ip
        self.prefix = prefix
        self.key = key
        self.port = port
    
    def match_by_ip(self, dst):
        dst = dst & self.prefix
        if dst & self.ip == self.ip:
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
        prefix = prefix[0] + "." + prefix[1] + "." + prefix[2] + "." + prefix[3]
        return b64encode(self.key) + " " + self.ip_s + " " + prefix

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
                break;
    
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