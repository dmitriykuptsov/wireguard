from crypto.curve25519 import X25519PrivateKey, X25519PublicKey
from os import urandom
import sys
import os
from base64 import b64encode, b64decode
sys.path.append(os.getcwd())
priv = X25519PrivateKey.from_private_bytes(urandom(32))
pub = X25519PublicKey.from_public_bytes(priv.public_key())
print("Private key: " + b64encode(priv.private_bytes()).decode("ASCII"))
print("Public key: " + b64encode(pub.public_bytes()).decode("ASCII"))
