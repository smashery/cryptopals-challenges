import time
import struct
from decode_xor import *

class MT19937(object):
    (w, n, m, r) = (32, 624, 397, 31)
    a = 0x9908B0DF
    (u, d) = (11, 0xFFFFFFFF)
    (s, b) = (7, 0x9D2C5680)
    (t, c) = (15, 0xEFC60000)
    f = 1812433253
    l = 18
    upper_mask = 0x80000000
    lower_mask = 0x7fffffff

    def __init__(self, seed):
        self.index = self.n
        self.MT = [seed]
        for i in range(1, self.n):
            self.MT.append(_int32((self.f * (self.MT[i - 1] ^ (self.MT[i - 1] >> (self.w - 2)))) + i))

    def extract_number(self):
        assert self.index <= self.n
        if self.index == self.n:
            self.twist()

        y = self.MT[self.index]
        y ^= ((y >> self.u) & self.d)
        y ^= ((y << self.s) & self.b)
        y ^= ((y << self.t) & self.c)
        y ^= (y >> self.l)

        self.index += 1
        return _int32(y)

    def twist(self):
        for i in range(0, self.n):
            x = _int32((self.MT[i] & self.upper_mask) + (self.MT[(i + 1) % self.n] & self.lower_mask))
            xA = x >> 1
            if x % 2 != 0:
                xA ^= self.a

            self.MT[i] = self.MT[(i + self.m) % self.n] ^ xA
        self.index = 0


def _int32(x):
    # Get the 32 least significant bits.
    return int(0xFFFFFFFF & x)

def find_mt19937_seed_in_range(low, high, first_output_value):
    for seed in range(low, high+1):
        m = MT19937(seed)
        if m.extract_number() == first_output_value:
            return seed
    return None


def find_mt19937_seed_in_last_n_seconds(n, first_output_value):
    current_time = int(time.time())
    return find_mt19937_seed_in_range(current_time - n, current_time, first_output_value)


def undo_shift_and_xor(number, shift, shift_right=True):
    # 'number' was produced by doing x ^ (x >> shift)
    # We want to find x
    # We can do this by starting with the highest bit in number
    # That bit must have been the highest bit in x, since its xor-partner
    # was bit-shifted down. We can use that as a "staging area" to figure
    # out the other bits
    x_single_byte_mask = 0x80000000
    x_shifted_single_byte_mask = x_single_byte_mask >> shift
    x = 0
    x_shifted = 0
    while x_single_byte_mask != 0:
        if (number ^ x_shifted) & x_single_byte_mask:
            x |= x_single_byte_mask
            x_shifted |= x_shifted_single_byte_mask

        x_single_byte_mask >>= 1
        x_shifted_single_byte_mask >>= 1
    if shift_right:
        return x
    else:
        return x_shifted


def undo_left_shift_xor_with_add(number, shift, and_value):
    # 'number' was produced by doing x ^ ((x << shift) & and_value)
    # We want to find x
    # Let's start at the bottom
    x_single_byte_mask = 0x1
    x_shifted_single_byte_mask = x_single_byte_mask << shift
    x = 0
    x_shifted = 0
    while x_single_byte_mask != 0x100000000:
        if (number ^ (x_shifted & and_value)) & x_single_byte_mask:
            x |= x_single_byte_mask
            x_shifted |= x_shifted_single_byte_mask

        x_single_byte_mask <<= 1
        x_shifted_single_byte_mask <<= 1
    return x


def get_mt_value(random_number):
    (u, d) = (11, 0xFFFFFFFF)
    (s, b) = (7, 0x9D2C5680)
    (t, c) = (15, 0xEFC60000)
    l = 18
    y = undo_shift_and_xor(random_number, l)

    y = undo_left_shift_xor_with_add(y, t, c)
    y = undo_left_shift_xor_with_add(y, s, b)
    y = undo_shift_and_xor(y, u)
    return y


def build_mt_from_random_numbers(random_numbers):
    assert len(random_numbers) == 624
    mt = map(get_mt_value, random_numbers)
    m = MT19937(0)
    m.MT = mt
    m.index = 0
    return m


def get_mt_key_stream(seed):
    m = MT19937(seed)
    while True:
        n = m.extract_number()
        packed = struct.pack('I', n)
        for c in packed:
            yield c


def encrypt_with_mt_stream(text, seed=None):
    if seed is None:
        seed = int(time.time())
    g = get_mt_key_stream(seed)
    return xor_bytes(text, g)

def find_seed_from_mt_stream_cipher(ciphertext, plaintext, search_range_start, search_range_end):
    key = xor_bytes(ciphertext, plaintext)
    first_int = struct.unpack('I', key[:4])[0]
    return find_mt19937_seed_in_range(search_range_start, search_range_end, first_int)