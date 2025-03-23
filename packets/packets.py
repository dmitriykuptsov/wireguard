WIREGUARD_INITIATOR_TYPE = 1
WIREGUARD_RESPONDER_TYPE = 2
WIREGUARD_COOKIE_REPLY_TYPE = 3
WIREGUARD_TRANSPORT_DATA_TYPE = 4

TYPE_LEGNTH = 1
TYPE_OFFSET = 0
RESERVED_LENGTH = 3

class WireGuardPacket(object):
    def __init__(self, buffer = None):
        if buffer:
            self.buffer = buffer
        else:
            self.buffer = bytearray ([0] * (TYPE_LEGNTH + RESERVED_LENGTH))
    def type(self, t = None):
        if t:
            self.buffer[TYPE_OFFSET] = t & 0xFF;
        else:
            return self.buffer[TYPE_OFFSET]
        
I_SENDER_LENGTH = 4
I_SENDER_OFFSET = 4
I_EPHIMERAL_LENGTH = 32
I_EPHIMERAL_OFFSET = 8
STATIC_LENGTH = 32 + 16
STATIC_OFFSET = 40
TIMESTAMP_LENGTH = 12 + 16
TIMESTAMP_OFFSET = 72 + 16
I_MAC1_LENGTH = 16
I_MAC1_OFFSET = 84 + 32
I_MAC2_LENGTH = 16
I_MAC2_OFFSET = 100 + 32
INITIATOR_MSG_ALPHA_OFFSET = 84 + 32
INITIATOR_MSG_BETA_OFFSET = 100 + 32

class WireGuardInitiatorPacket(WireGuardPacket):
    def __init__(self, buffer = None):
        if buffer:
            self.buffer = buffer
        else:
            self.buffer = bytearray([0] * (TYPE_LEGNTH + RESERVED_LENGTH + \
                                             I_SENDER_LENGTH + \
                                                I_EPHIMERAL_LENGTH + \
                                                    STATIC_LENGTH + \
                                                        TIMESTAMP_LENGTH + \
                                                            MAC1_LENGTH + \
                                                                MAC2_LENGTH))
            self.buffer[TYPE_OFFSET] = WIREGUARD_INITIATOR_TYPE
        #self.type(WIREGUARD_INITIATOR_TYPE)

    def sender(self, s = None):
        if s:
            self.buffer[I_SENDER_OFFSET:I_SENDER_OFFSET+I_SENDER_LENGTH] = s
        else:
            return self.buffer[I_SENDER_OFFSET:I_SENDER_OFFSET+I_SENDER_LENGTH]

    def ephimeral(self, e = None):
        if e:
            self.buffer[I_EPHIMERAL_OFFSET:I_EPHIMERAL_LENGTH+I_EPHIMERAL_OFFSET] = e
        else:
            return self.buffer[I_EPHIMERAL_OFFSET:I_EPHIMERAL_LENGTH+I_EPHIMERAL_OFFSET]
        
    def static(self, s = None):
        if s:
            self.buffer[STATIC_OFFSET:STATIC_LENGTH+STATIC_OFFSET] = s
        else:
            return self.buffer[STATIC_OFFSET:STATIC_LENGTH+STATIC_OFFSET]

    def timestamp(self, t = None):
        if t:
            self.buffer[TIMESTAMP_OFFSET:TIMESTAMP_LENGTH+TIMESTAMP_OFFSET] = t
        else:
            return self.buffer[TIMESTAMP_OFFSET:TIMESTAMP_LENGTH+TIMESTAMP_OFFSET]
        
    def mac1(self, m = None):
        if m:
            self.buffer[I_MAC1_OFFSET:I_MAC1_LENGTH+I_MAC1_OFFSET] = m
        else:
            return self.buffer[I_MAC1_OFFSET:I_MAC1_LENGTH+I_MAC1_OFFSET]
        
    def mac2(self, m = None):
        if m:
            self.buffer[I_MAC2_OFFSET:I_MAC2_LENGTH+I_MAC2_OFFSET] = m
        else:
            return self.buffer[I_MAC2_OFFSET:I_MAC2_LENGTH+I_MAC2_OFFSET]

R_SENDER_LENGTH = 4
R_SENDER_OFFSET = 4
R_RECEIVER_LENGTH = 4
R_RECEIVER_OFFSET = 8
EPHIMERAL_LENGTH = 32
EPHIMERAL_OFFSET = 12
EMPTY_LENGTH = 16
EMPTY_OFFSET = 44
MAC1_LENGTH = 16
MAC1_OFFSET = 60
MAC2_LENGTH = 16
MAC2_OFFSET = 76
RESPONDER_MSG_ALPHA_OFFSET = 60
RESPONDER_MSG_BETA_OFFSET = 76

class WireGuardResponderPacket(WireGuardPacket):
    def __init__(self, buffer = None):
        if buffer:
            self.buffer = buffer
        else:
            self.buffer = bytearray([0] * (TYPE_LEGNTH + RESERVED_LENGTH + R_SENDER_LENGTH + R_RECEIVER_LENGTH + \
                                             EPHIMERAL_LENGTH + MAC1_LENGTH + MAC2_LENGTH))
            self.buffer[TYPE_OFFSET] = WIREGUARD_RESPONDER_TYPE
        #self.type(WIREGUARD_RESPONDER_TYPE)
    def sender(self, s = None):
        if s:
            self.buffer[R_SENDER_OFFSET:R_SENDER_OFFSET+R_SENDER_LENGTH] = s
        else:
            return self.buffer[R_SENDER_OFFSET:R_SENDER_OFFSET+R_SENDER_LENGTH]
    
    def receiver(self, r = None):
        if r:
            self.buffer[R_RECEIVER_OFFSET:R_RECEIVER_OFFSET+R_RECEIVER_LENGTH] = r
        else:
            return self.buffer[R_RECEIVER_OFFSET:R_RECEIVER_OFFSET+R_RECEIVER_LENGTH]

    def ephimeral(self, e = None):
        if e:
            self.buffer[EPHIMERAL_OFFSET:EPHIMERAL_LENGTH+EPHIMERAL_OFFSET] = e
        else:
            return self.buffer[EPHIMERAL_OFFSET:EPHIMERAL_LENGTH+EPHIMERAL_OFFSET]
    
    def empty(self, e = None):
        if e:
            self.buffer[EMPTY_OFFSET:EMPTY_LENGTH+EMPTY_OFFSET] = e
        else:
            return self.buffer[EMPTY_OFFSET:EMPTY_LENGTH+EMPTY_OFFSET]
    
    def mac1(self, m = None):
        if m:
            self.buffer[MAC1_OFFSET:MAC1_LENGTH+MAC1_OFFSET] = m
        else:
            return self.buffer[MAC1_OFFSET:MAC1_LENGTH+MAC1_OFFSET]
        
    def mac2(self, m = None):
        if m:
            self.buffer[MAC2_OFFSET:MAC2_LENGTH+MAC2_OFFSET] = m
        else:
            return self.buffer[MAC2_OFFSET:MAC2_LENGTH+MAC2_OFFSET]
        
D_RECEIVER_LENGTH = 4
D_RECEIVER_OFFSET = 4
COUNTER_LENGTH = 8
COUNTER_OFFSET = 8
DATA_OFFSET = 16
class WireGuardDataPacket(WireGuardPacket):
    def __init__(self, buffer = None):
        if buffer:
            self.buffer = buffer
        else:
            self.buffer = bytearray([0] * (TYPE_LEGNTH + RESERVED_LENGTH + \
                                             RECEIVER_LENGTH + COUNTER_LENGTH))
            self.buffer[TYPE_OFFSET] = WIREGUARD_TRANSPORT_DATA_TYPE
        #self.type(WIREGUARD_TRANSPORT_DATA_TYPE)
    def receiver(self, r = None):
        if r:
            self.buffer[D_RECEIVER_OFFSET:D_RECEIVER_OFFSET+D_RECEIVER_LENGTH] = r
        else:
            return self.buffer[D_RECEIVER_OFFSET:D_RECEIVER_OFFSET+D_RECEIVER_LENGTH]
    
    def counter(self, c = None):
        if c:
            self.buffer[COUNTER_OFFSET:COUNTER_OFFSET+COUNTER_LENGTH] = c
        else:
            return self.buffer[COUNTER_OFFSET:COUNTER_OFFSET+COUNTER_LENGTH]
    
    def data(self, d = None):
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
    def __init__(self, buffer = None):
        if buffer:
            self.buffer = buffer
        else:
            self.buffer = bytearray([0] * (TYPE_LEGNTH + RESERVED_LENGTH + RECEIVER_LENGTH + \
                                             NONCE_LENGTH + COOKIE_LENGTH))
            self.buffer[TYPE_OFFSET] = WIREGUARD_COOKIE_REPLY_TYPE
        #self.type(WIREGUARD_COOKIE_REPLY_TYPE)
    def receiver(self, r = None):
        if r:
            self.buffer[RECEIVER_OFFSET:RECEIVER_OFFSET+RECEIVER_LENGTH] = r
        else:
            return self.buffer[RECEIVER_OFFSET:RECEIVER_OFFSET+RECEIVER_LENGTH]
    
    def nonce(self, c = None):
        if c:
            self.buffer[NONCE_OFFSET:NONCE_OFFSET+NONCE_LENGTH] = c
        else:
            return self.buffer[NONCE_OFFSET:NONCE_OFFSET+NONCE_LENGTH]
    
    def cookie(self, d = None):
        if d:
            self.buffer[COOKIE_OFFSET:COOKIE_OFFSET+COOKIE_LENGTH] = d
        else:
            return self.buffer[COOKIE_OFFSET:COOKIE_OFFSET+COOKIE_LENGTH]