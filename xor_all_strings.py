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
from Crypto.Cipher import AES


global_key = '\xf0\xff\x64\x36\x74\x34\xd8\x67\x43\x67\x43\x6a\x92\x29\xee\xd7'


def create_aes_key():
    return os.urandom(16)


f = open(r'Input\25.txt')
text = base64.decodestring(f.read())
print (text)