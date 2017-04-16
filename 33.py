from Crypto.Util import number
from Crypto.Cipher import AES
from hashes import *
from block_encryption import *
import os

n_length = 1024


def binconvert(n):
    barray = []
    if n < 0:
        raise ValueError, "must be positive"
    if n == 0:
        return 0
    while n > 0:
        # barray = n%2 + barray[:]
        barray.append(n % 2)
        n = n >> 1
    barray.reverse()
    return barray

# y**x mod n
def modexp(y, x, n):
    # convert x to a binary list
    x = binconvert(x)

    s = [1]
    r = x[:]
    for k in range(0, len(x)):
        if x[k] == 1:
            r[k] = (s[k] * y) % n
        else:
            r[k] = s[k]
        s.append((r[k] ** 2) % n)
    # print s
    # print r
    return r[-1]

class DiffieHelmanParticipant(object):
    def __init__(self, p, g):
        self.p = p
        self.g = g
        self.private_key = number.getPrime(n_length)
        self.shared_secret = None

    def public_key(self):
        return modexp(self.g, self.private_key, self.p)

    def create_shared_secret(self, partners_public_key):
        self.shared_secret = modexp(partners_public_key, self.private_key, self.p)

    def encrypt_message(self, text):
        text = pad_pkcs7(text, 16)
        assert self.shared_secret is not None
        iv = os.urandom(16)
        hex_string = '%x' % self.shared_secret
        c = AES.AESCipher(sha1(binascii.unhexlify(hex_string))[:16], IV=iv)
        return c.encrypt(text), iv

    def decrypt_message(self, ciphertext, iv):
        assert self.shared_secret is not None
        hex_string = '%x' % self.shared_secret
        c = AES.AESCipher(sha1(binascii.unhexlify(hex_string))[:16], IV=iv)
        return strip_pkcs7_padding(c.decrypt(ciphertext))



p = number.getPrime(n_length)

g = 2
alice = DiffieHelmanParticipant(p, g)
bob = DiffieHelmanParticipant(p, g)
print 'Keys set up'
bob.create_shared_secret(alice.public_key())

alice.create_shared_secret(bob.public_key())
print 'Shared secret created. Encrypting'

iv, ciphertext = bob.encrypt_message('hello there')
print alice.decrypt_message(iv, ciphertext)