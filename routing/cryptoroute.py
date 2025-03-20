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
    state  = None
    rekey_timeout = 0

    def __init__(self, ip_s, ip, prefix, key, port):
        self.ip_s = ip_s
        self.ip = ip
        self.prefix = prefix
        self.key = key
        self.port = port
    def match(self, dst):
        dst = dst & self.prefix
        if dst & self.ip == self.ip:
            return True
        return False

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
        self.table.sort(recmp)
    def delete(self, entry):
        for e in self.table:
            if e.key == entry.key:
                self.table.remove(e)
                break;
    def get(self, ip):
        for e in self.table:
            if e.match(ip):
                return e
        return None
    