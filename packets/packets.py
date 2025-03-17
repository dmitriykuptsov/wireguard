WIREGUARD_INITIATOR_TYPE = 1
WIREGUARD_RESPONDER_TYPE = 2
WIREGUARD_COOKIE_REPLY_TYPE = 3
WIREGUARD_TRANSPORT_DATA_TYPE = 4

TYPE_LEGNTH = 1
TYPE_OFFSET = 0
RESERVED_LENGTH = 3

class WireGuardPacket(object):
    def __init__(self, buffer):
        if buffer:
            self.buffer = buffer
        else:
            self.buffer = (bytearray) [0] * (TYPE_LEGNTH + RESERVED_LENGTH)
    def type(self, type):
        if type:
            self.buffer[TYPE_OFFSET] = type & 0xFF;
        else:
            return self.buffer[TYPE_OFFSET]
        
SENDER_LENGTH = 4
SENDER_OFFSET = 4
EPHIMERAL_LENGTH = 32
EPHIMERAL_OFFSET = 8
STATIC_LENGTH = 32
STATIC_OFFSET = 40
TIMESTAMP_LENGTH = 12
TIMESTAMP_OFFSET = 72
MAC1_LENGTH = 16
MAC1_OFFSET = 84
MAC2_LENGTH = 16
MAC2_OFFSET = 100

class WireGuardInitiatorPacket(WireGuardPacket):
    def __init__(self, buffer):
        if buffer:
            self.buffer = buffer
        else:
            self.buffer = (bytearray) [0] * (TYPE_LEGNTH + RESERVED_LENGTH + \
                                             SENDER_LENGTH + \
                                                STATIC_LENGTH + \
                                                    TIMESTAMP_LENGTH + \
                                                        MAC1_LENGTH + \
                                                            MAC2_LENGTH)
            self.buffer[TYPE_OFFSET] = WIREGUARD_INITIATOR_TYPE

    def sender(self, s):
        if s:
            self.buffer[SENDER_OFFSET:SENDER_OFFSET+SENDER_LENGTH] = s
        else:
            return self.buffer[SENDER_OFFSET:SENDER_OFFSET+SENDER_LENGTH]

    def ephimeral(self, e):
        if e:
            self.buffer[EPHIMERAL_OFFSET:EPHIMERAL_LENGTH+EPHIMERAL_OFFSET] = e
        else:
            return self.buffer[EPHIMERAL_OFFSET:EPHIMERAL_LENGTH+EPHIMERAL_OFFSET]
        
    def static(self, s):
        if s:
            self.buffer[STATIC_OFFSET:STATIC_LENGTH+STATIC_OFFSET] = s
        else:
            return self.buffer[STATIC_OFFSET:STATIC_LENGTH+STATIC_OFFSET]

    def timestamp(self, t):
        if t:
            self.buffer[TIMESTAMP_OFFSET:TIMESTAMP_LENGTH+TIMESTAMP_OFFSET] = t
        else:
            return self.buffer[TIMESTAMP_OFFSET:TIMESTAMP_LENGTH+TIMESTAMP_OFFSET]
        
    def mac1(self, m):
        if m:
            self.buffer[MAC1_OFFSET:MAC1_LENGTH+MAC1_OFFSET] = m
        else:
            return self.buffer[MAC1_OFFSET:MAC1_LENGTH+MAC1_OFFSET]
        
    def mac2(self, m):
        if m:
            self.buffer[MAC2_OFFSET:MAC2_LENGTH+MAC2_OFFSET] = m
        else:
            return self.buffer[MAC2_OFFSET:MAC2_LENGTH+MAC2_OFFSET]

SENDER_LENGTH = 4
SENDER_OFFSET = 4
RECEIVER_LENGTH = 4
RECEIVER_OFFSET = 8
EPHIMERAL_LENGTH = 32
EPHIMERAL_OFFSET = 12
MAC1_LENGTH = 16
MAC1_OFFSET = 44
MAC2_LENGTH = 16
MAC2_OFFSET = 60

class WireGuardResponderPacket(WireGuardPacket):
    def __init__(self, buffer):
        if buffer:
            self.buffer = buffer
        else:
            self.buffer = (bytearray) [0] * (TYPE_LEGNTH + RESERVED_LENGTH + SENDER_LENGTH + \
                                             EPHIMERAL_LENGTH + MAC1_LENGTH + MAC2_LENGTH)
            self.buffer[TYPE_OFFSET] = WIREGUARD_RESPONDER_TYPE
    def sender(self, s):
        if s:
            self.buffer[SENDER_OFFSET:SENDER_OFFSET+SENDER_LENGTH] = s
        else:
            return self.buffer[SENDER_OFFSET:SENDER_OFFSET+SENDER_LENGTH]
    
    def receiver(self, r):
        if r:
            self.buffer[RECEIVER_OFFSET:RECEIVER_OFFSET+RECEIVER_LENGTH] = r
        else:
            return self.buffer[RECEIVER_OFFSET:RECEIVER_OFFSET+RECEIVER_LENGTH]

    def ephimeral(self, e):
        if e:
            self.buffer[EPHIMERAL_OFFSET:EPHIMERAL_LENGTH+EPHIMERAL_OFFSET] = e
        else:
            return self.buffer[EPHIMERAL_OFFSET:EPHIMERAL_LENGTH+EPHIMERAL_OFFSET]
    
    def mac1(self, m):
        if m:
            self.buffer[MAC1_OFFSET:MAC1_LENGTH+MAC1_OFFSET] = m
        else:
            return self.buffer[MAC1_OFFSET:MAC1_LENGTH+MAC1_OFFSET]
        
    def mac2(self, m):
        if m:
            self.buffer[MAC2_OFFSET:MAC2_LENGTH+MAC2_OFFSET] = m
        else:
            return self.buffer[MAC2_OFFSET:MAC2_LENGTH+MAC2_OFFSET]
        
RECEIVER_LENGTH = 4
RECEIVER_OFFSET = 4
COUNTER_LENGTH = 8
COUNTER_OFFSET = 8
DATA_OFFSET = 16
class WireGuardDataPacket(WireGuardPacket):
    def __init__(self, buffer):
        if buffer:
            self.buffer = buffer
        else:
            self.buffer = (bytearray) [0] * (TYPE_LEGNTH + RESERVED_LENGTH + SENDER_LENGTH + \
                                             RECEIVER_LENGTH + COUNTER_LENGTH)
            self.buffer[TYPE_OFFSET] = WIREGUARD_TRANSPORT_DATA_TYPE
    def receiver(self, r):
        if r:
            self.buffer[RECEIVER_OFFSET:RECEIVER_OFFSET+RECEIVER_LENGTH] = r
        else:
            return self.buffer[RECEIVER_OFFSET:RECEIVER_OFFSET+RECEIVER_LENGTH]
    
    def counter(self, c):
        if c:
            self.buffer[COUNTER_OFFSET:COUNTER_OFFSET+COUNTER_LENGTH] = c
        else:
            return self.buffer[COUNTER_OFFSET:COUNTER_OFFSET+COUNTER_LENGTH]
    
    def data(self, d):
        if d:
            self.buffer[DATA_OFFSET:DATA_OFFSET+len(d)] = d
        else:
            return self.buffer[DATA_OFFSET:]
        
RECEIVER_LENGTH = 4
RECEIVER_OFFSET = 4
NONCE_LENGTH = 24
NONCE_OFFSET = 8
COOKIE_LENGTH = 16
COOKIE_OFFSET = 34

class WireGuardCookiePacket(WireGuardPacket):
    def __init__(self, buffer):
        if buffer:
            self.buffer = buffer
        else:
            self.buffer = (bytearray) [0] * (TYPE_LEGNTH + RESERVED_LENGTH + RECEIVER_LENGTH + \
                                             NONCE_LENGTH + COOKIE_LENGTH)
            self.buffer[TYPE_OFFSET] = WIREGUARD_COOKIE_REPLY_TYPE
    def receiver(self, r):
        if r:
            self.buffer[RECEIVER_OFFSET:RECEIVER_OFFSET+RECEIVER_LENGTH] = r
        else:
            return self.buffer[RECEIVER_OFFSET:RECEIVER_OFFSET+RECEIVER_LENGTH]
    
    def nonce(self, c):
        if c:
            self.buffer[NONCE_OFFSET:NONCE_OFFSET+NONCE_LENGTH] = c
        else:
            return self.buffer[NONCE_OFFSET:NONCE_OFFSET+NONCE_LENGTH]
    
    def cookie(self, d):
        if d:
            self.buffer[COOKIE_OFFSET:DATA_OFFSET+COOKIE_LENGTH] = d
        else:
            return self.buffer[COOKIE_OFFSET:DATA_OFFSET+COOKIE_LENGTH]