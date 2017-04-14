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

global_key = os.urandom(16)
nonce = os.urandom(16)

def create_encrypted_url(text):
    text = text.replace('=', '').replace(';', '')
    url = "comment1=cooking%20MCs;userdata=" + text + ";comment2=%20like%20a%20pound%20of%20bacon"
    url = pad_pkcs7(url, 16)
    c = AES.AESCipher(global_key, mode=AES.MODE_CTR, counter=lambda:nonce)
    return c.encrypt(url)


new_ciphertext = insert_text_into_ctr(create_encrypted_url, ';admin=true;')

c = AES.AESCipher(global_key, mode=AES.MODE_CTR, counter=lambda: nonce)
print c.decrypt(new_ciphertext)