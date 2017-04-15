from sha1 import *
from decode_xor import *


def hmac_sha1(key, message):
    blocksize = 64
    if len(key) > blocksize:
        key = sha1(key) # keys longer than blocksize are shortened
    if len(key) < blocksize:
        # keys shorter than blocksize are zero-padded
        key = key + '\x00' * (blocksize - len(key))

    o_key_pad = xor_bytes('\x5c' * blocksize, key)
    i_key_pad = xor_bytes('\x36' * blocksize, key)

    return sha1(o_key_pad + sha1(i_key_pad + message))

def add_sha1_padding(text):
    # append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
    # is congruent to 56 (mod 64)
    original_length = len(text)
    text += b'\x80'
    padding_needed = ((56 - (len(text)) % 64) % 64)
    text += b'\x00' * padding_needed
    assert len(text) % 64 == 56
    message_bit_length = original_length * 8
    text += struct.pack(b'>Q', message_bit_length)
    return text


def append_to_end_of_message_and_create_new_mac(mac, suffix, message_length_guess):
    """
    Add items to the end of a message and still produce a valid mac, without knowing
    the key.
    :param mac: The original mac, in raw bytes
    :param suffix: The suffix we wish to add
    :param message_length_guess: The length we think the message was, including the key
    :return: A new MAC, in raw bytes
    """
    assert message_length_guess % 64 == 0
    # Create new MAC
    sha_obj = create_sha_object_from_sha_value(mac, message_length_guess)
    return sha_obj.update(suffix).digest()


def create_sha_object_from_sha_value(sha_bytes, message_length_guess):
    assert message_length_guess % 64 == 0
    sha_obj = Sha1Hash()
    h = struct.unpack('>IIIII', sha_bytes)
    sha_obj._h = h
    sha_obj._message_byte_length = message_length_guess
    return sha_obj
