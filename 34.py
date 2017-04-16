from Crypto.Util import number
import hashlib
import os
from public_key import *
from hashes import *

n_length = 1024


class Server(object):
    def __init__(self):
        self.k = 3
        self.g = 2
        self.N = number.getPrime(n_length)
        self.private_key = number.getRandomInteger(n_length)
        self.username = 'Ringo'
        self.password = 'YELLOW SUBMARINE'

        self.salt = os.urandom(16)
        xH = hashlib.sha256(self.salt + self.password).hexdigest()
        x = int(xH, 16)
        self.v = modexp(self.g, x, self.N)

    def send_constants(self):
        return self.N, self.g, self.k

    def receive_username_and_client_public_key(self, username, client_public_key):
        self.public_key = self.k * self.v + modexp(self.g, self.private_key, self.N)
        self.requested_username = username
        self.client_public_key = client_public_key
        uH = hashlib.sha256(bigint_to_bytes(client_public_key) + bigint_to_bytes(self.public_key)).hexdigest()
        u = int(uH, 16)
        S = modexp(client_public_key * modexp(self.v, u, self.N), self.private_key, self.N)
        self.K = hashlib.sha256(bigint_to_bytes(S)).digest()

    def send_salt_and_public_key(self):
        return self.salt, self.public_key

    def validate_hmac(self, client_hmac_256):
        server_hmac = hmac(self.K, self.salt, lambda x: hashlib.sha256(x).hexdigest())
        return server_hmac == client_hmac_256


class Client(object):
    def __init__(self):
        self.k = None
        self.g = None
        self.N = None
        self.private_key = number.getRandomInteger(n_length)
        self.password = 'YELLOW SUBMARINE'
        self.username = 'Ringo'

    def receive_constants(self, N, g, k):
        self.k = k
        self.g = g
        self.N = N

    def send_username_and_public_key(self):
        self.public_key = modexp(self.g, self.private_key, self.N)
        return self.username, self.public_key

    def receive_salt_and_server_public_key(self, salt, server_public_key):
        uH = hashlib.sha256(bigint_to_bytes(self.public_key) + bigint_to_bytes(server_public_key)).hexdigest()
        u = int(uH, 16)
        xH = hashlib.sha256(salt + self.password).hexdigest()
        x = int(xH, 16)
        S = modexp(server_public_key - self.k * modexp(self.g, x, self.N), (self.private_key+ u * x), self.N)
        self.K = hashlib.sha256(bigint_to_bytes(S)).digest()
        self.salt = salt

    def send_hmac_256(self):
        return hmac(self.K, self.salt, lambda x: hashlib.sha256(x).hexdigest())

class CheatingClient(Client):
    def __init__(self, multiplier):
        self.multiplier = multiplier
        self.k = None
        self.g = None
        self.N = None
        self.private_key = number.getRandomInteger(n_length)
        self.password = 'I have no idea what the password is'
        self.username = 'Ringo'

    def send_username_and_public_key(self):
        self.public_key = self.N * self.multiplier
        return self.username, self.public_key

    def receive_salt_and_server_public_key(self, salt, server_public_key):
        self.K = hashlib.sha256(bigint_to_bytes(0)).digest()
        self.salt = salt


def demo_srp(s, c):
    c.receive_constants(*s.send_constants())
    s.receive_username_and_client_public_key(*c.send_username_and_public_key())
    c.receive_salt_and_server_public_key(*s.send_salt_and_public_key())
    return s.validate_hmac(c.send_hmac_256())


def demo_srp_working():
    return demo_srp(Server(), Client())


def demo_srp_broken():
    return demo_srp(Server(), CheatingClient(5))

print demo_srp_broken()