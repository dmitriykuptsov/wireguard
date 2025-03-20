from Crypto.Cipher import ChaCha20_Poly1305

class AEAD():
    def __init__(self, key, counter):
        if len(key) != 32:
            raise ValueError("key must be 32 bytes")
        if len(counter) != 8:
            raise ValueError("counter must be 8 bytes")
        counter = bytes([0x0] * 4) + counter
        self.key = key
        self.counter = counter

    def encrypt(self, data, auth):
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=self.counter)
        cipher.update(auth)
        return cipher.encrypt(data)
    
    def encrypt_and_digest(self, data, auth):
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=self.counter)
        cipher.update(auth)
        return cipher.encrypt_and_digest(data)
    
    def decrypt(self, data, auth):
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=self.counter)
        cipher.update(auth)
        return cipher.decrypt(data)
    
    def decrypt_and_verify(self, data, auth, tag):
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=self.counter)
        cipher.update(auth)
        return cipher.decrypt_and_verify(data, tag)
    

class xAEAD():
    def __init__(self, key, nonce):
        if len(key) != 32:
            raise ValueError("key must be 32 bytes")
        if len(nonce) != 24:
            raise ValueError("nonce must be 24 bytes")
        self.key = key
        self.nonce = nonce

    def encrypt(self, data, auth):
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=self.nonce)
        cipher.update(auth)
        return cipher.encrypt(data)
    
    def encrypt_and_digest(self, data, auth):
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=self.nonce)
        cipher.update(auth)
        return cipher.encrypt_and_digest(data)
    
    def decrypt(self, data, auth):
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=self.nonce)
        cipher.update(auth)
        return cipher.decrypt(data)
    
    def decrypt_and_verify(self, data, auth, tag):
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=self.nonce)
        cipher.update(auth)
        return cipher.decrypt_and_verify(data, tag)
        
#import os
#key = os.urandom(32)
#counter = os.urandom(8)
#c = AEAD(key, counter)
#data = b'Hello, world!'
#ad = b'Header!'
#(cipher, tag) = c.encrypt_and_digest(data, ad)
#c = AEAD(key, counter)
#data = b'Hello, world!'
#ad = b'Header!'
#print(c.decrypt_and_verify(cipher, ad, tag))