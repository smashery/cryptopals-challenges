from Crypto.Util import number
from Crypto.Cipher import AES
from hashes import *
from block_encryption import *
from public_key import *
import os

n_length = 1024


class DiffieHellmanParticipant(object):
    def choose_p_and_g(self):
        self.__g = 2
        self.__p = number.getPrime(n_length)
        self.__select_private_key()

    def learn_parameters(self, p, g, partners_public_key):
        self.__g = g
        self.__p = p
        self.__select_private_key()
        self.create_shared_secret(partners_public_key)

    def __select_private_key(self):
        self.__private_key = number.getRandomInteger(n_length)

    def public_key(self):
        return modexp(self.__g, self.__private_key, self.__p)

    def p_g_and_public_key(self):
        return self.__p, self.__g, self.public_key()

    def create_shared_secret(self, partners_public_key):
        self.__shared_secret = modexp(partners_public_key, self.__private_key, self.__p)

    def encrypt_message(self, text):
        text = pad_pkcs7(text, 16)
        assert self.__shared_secret is not None
        iv = os.urandom(16)
        hex_string = '%0256x' % self.__shared_secret
        c = AES.AESCipher(sha1(binascii.unhexlify(hex_string))[:16], IV=iv)
        return c.encrypt(text), iv

    def decrypt_message(self, ciphertext, iv):
        assert self.__shared_secret is not None
        hex_string = '%0128x' % self.__shared_secret
        c = AES.AESCipher(sha1(binascii.unhexlify(hex_string))[:16], IV=iv)
        return strip_pkcs7_padding(c.decrypt(ciphertext))


def demo_diffie_hellman_properly():
    alice = DiffieHellmanParticipant()
    bob = DiffieHellmanParticipant()
    alice.choose_p_and_g()
    bob.learn_parameters(*alice.p_g_and_public_key())
    alice.create_shared_secret(bob.public_key())

    print 'Shared secret created. Encrypting'

    iv, ciphertext = bob.encrypt_message('hello there')
    print alice.decrypt_message(iv, ciphertext)


def demo_breaking_diffie_hellman_change_public_key():
    alice = DiffieHellmanParticipant()
    bob = DiffieHellmanParticipant()
    alice.choose_p_and_g()
    p, g, A = alice.p_g_and_public_key()
    bob.learn_parameters(p, g, p) # Mallory passes p in twice
    B = bob.public_key()
    alice.create_shared_secret(p) # Mallory ignores

    print 'Shared secret created. Encrypting'

    ciphertext, iv = bob.encrypt_message('hello there')

    # We should have forced the shared_secret to be 0
    hex_string = '%0256x' % 0
    c = AES.AESCipher(sha1(binascii.unhexlify(hex_string))[:16], IV=iv)
    print strip_pkcs7_padding(c.decrypt(ciphertext))


def demo_breaking_diffie_hellman_change_g_to_1():
    alice = DiffieHellmanParticipant()
    bob = DiffieHellmanParticipant()
    alice.choose_p_and_g()
    p, g, A = alice.p_g_and_public_key()
    bob.learn_parameters(p, 1, A) # Mallory changes g to 1
    B = bob.public_key()
    assert B == 1
    alice.create_shared_secret(B)
    # Alice's shared secret should now be 1.

    print 'Shared secret created. Encrypting'

    ciphertext, iv = alice.encrypt_message('hello there')

    # We should have forced the shared_secret to be 1
    hex_string = '%0256x' % 1
    c = AES.AESCipher(sha1(binascii.unhexlify(hex_string))[:16], IV=iv)
    print strip_pkcs7_padding(c.decrypt(ciphertext))


def demo_breaking_diffie_hellman_change_g_to_p():
    alice = DiffieHellmanParticipant()
    bob = DiffieHellmanParticipant()
    alice.choose_p_and_g()
    p, g, A = alice.p_g_and_public_key()
    bob.learn_parameters(p, p, A) # Mallory changes g to p
    B = bob.public_key()
    assert B == 0
    alice.create_shared_secret(B)
    # Alice's shared secret should now be 0.

    print 'Shared secret created. Encrypting'

    ciphertext, iv = alice.encrypt_message('hello there')

    hex_string = '%0256x' % 0
    c = AES.AESCipher(sha1(binascii.unhexlify(hex_string))[:16], IV=iv)
    print strip_pkcs7_padding(c.decrypt(ciphertext))

def demo_breaking_diffie_hellman_change_g_to_p_minus_1():
    alice = DiffieHellmanParticipant()
    bob = DiffieHellmanParticipant()
    alice.choose_p_and_g()
    p, g, A = alice.p_g_and_public_key()
    bob.learn_parameters(p, p-1, A)  # Mallory changes g to p-1
    B = bob.public_key()
    alice.create_shared_secret(B)
    # Alice's shared secret is now either B or 1, something something fermat

    print 'Shared secret created. Encrypting'

    ciphertext, iv = alice.encrypt_message('hello there')

    hex_string = '%0256x' % B
    c = AES.AESCipher(sha1(binascii.unhexlify(hex_string))[:16], IV=iv)
    print strip_pkcs7_padding(c.decrypt(ciphertext))


demo_breaking_diffie_hellman_change_g_to_p_minus_1()