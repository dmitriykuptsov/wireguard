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
