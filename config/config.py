class Config():
    parameters = {}

    KEY = "private"
    PORT = "port"
    PEER = "peer"
    LOCAL = "local"

    def __init__(self, filename):
        fd = open(filename)
        lines = fd.readlines()
        for line in lines:
            s = line.split(":")
            self.parameters[s[0]] = s[1].strip()

    def get(self, key):
        return self.parameters.get(key)
