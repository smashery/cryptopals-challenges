import os
from hashes import *

message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
key = os.urandom(16)

mac = create_sha1_mac(message, key)


suffix = ';admin=true'

message_length = (len(key+message) / 64 + 1) * 64
new_mac = append_to_end_of_message_and_create_new_mac(mac, suffix, message_length)

# Test our work
padded_message = add_sha1_padding(key+message)
payloaded_message = padded_message + suffix

print sha1(payloaded_message, pretty_print=True)
print new_mac