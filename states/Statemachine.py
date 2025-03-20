Rekey_After_Messages = 2**60
Reject_After_Messages = 2**64 - 2**18 - 1
Rekey_After_Time = 120 # seconds
Reject_After_Time = 180 # seconds
Rekey_Attempt_Time = 90 # seconds
Rekey_Timeout = 5 # seconds
Keepalive_Timeout = 10 # seconds

class States():
    UNASSOCIATED = 0
    I_SENT = 1
    R_SENT = 2
    ESTABLISHED = 3

    def __init__(self):
        self.state = self.UNASSOCIATED
    
    def set_state(self, state):
        self.state = state
    
    def get_state(self):
        return self.state
    
    def __str__(self):
        if self.state == self.UNASSOCIATED:
            return "UNASSOCIATED"
        if self.state == self.I_SENT:
            return "I_SENT"
        if self.state == self.R_SENT:
            return "R_SENT"
        if self.state == self.ESTABLISHED:
            return "ESTABLISHED"

class SA():
    def __init__(self):
        self.I = 0
        self.R = 0
        self.Spriv = None
        self.Spub = None
        self.Epriv = None
        self.Epub = None
        self.TSend = None
        self.TRecv = None
        self.NSend = 0
        self.NRecv = 0
        self.peer_addr = None
        self.peer_port = None

class Storage():

    def __init__(self):
        self.store = {}

    def get_record(self, key):
        return self.store.get(key, None)
    
    def set_record(self, key: str, record: object):
        self.store[key] = record
