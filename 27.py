from decode_xor import *
from block_encryption import *
from stream_cipher import *
from mersenne_twister import *
import binascii
import base64
import itertools
import os
import random
import struct
import collections
import string
import re
from Crypto.Cipher import AES

global_key = os.urandom(16)
nonce = os.urandom(16)


def create_encrypted_url(text):
    text = text.replace('=', '').replace(';', '')
    url = "comment1=cooking%20MCs;userdata=" + text + ";comment2=%20like%20a%20pound%20of%20bacon"
    url = pad_pkcs7(url, 16)
    c = AES.AESCipher(global_key, mode=AES.MODE_CBC, IV=global_key)
    return c.encrypt(url)


def decrypt(ciphertext):
    c = AES.AESCipher(global_key, mode=AES.MODE_CBC, IV=global_key)
    result = c.decrypt(ciphertext)
    for char in result:
        if not char in string.printable:
            raise InvalidMessageException('Unprintable characters: ' + result)



print get_key_from_same_iv_as_key(create_encrypted_url, decrypt) == global_key