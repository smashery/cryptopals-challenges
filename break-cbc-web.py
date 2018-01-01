import base64
import requests
import grequests
import urllib
from block_encryption import *


def make_async_request(ciphertext):
    cookie = {}
    return grequests.get('http://url',timeout=120, cookies=cookie)

def check_async_request(response):
    return 'PKCS' in response.text

def cookie_oracle(ciphertext):
    cookie = {}
    r = requests.get('http://url', cookies=cookie)
    return 'PKCS' in r.content


#decrypt_cbc_using_padding_attack(word, cookie_oracle, 8, skip_blocks=2)
desired_text = 'inject here'
result = insert_text_with_cbc_bitflip(make_async_request, check_async_request, desired_text, 8)
print(result)
print(base64.b64encode(result))
print(map(ord,result))