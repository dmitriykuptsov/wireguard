from os import urandom
from base64 import b64encode, b64decode

priv = urandom(32)
print(b64encode(priv).decode("ASCII"))