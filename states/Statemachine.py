RekeyAfterMessages = 2**60
RejectAfterMessages = 2**64 - 2**18 - 1
RekeyAfterTime = 120  # seconds
RejectAfterTime = 180  # seconds
RekeyAttemptTime = 90  # seconds
RekeyTimeout = 5  # seconds
KeepaliveTimeout = 10  # seconds
SequenceWindow = 10


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
