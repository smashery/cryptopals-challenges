import binascii
import collections
import itertools
import string

expectedFrequencies = {'a':8.17,'b':1.49,'c':2.78,'d':4.25,'e':12.70,'f':2.23,'g':2.02,'h':6.09,'i':6.97,'j':0.15,'k':0.77,'l':4.03,'m':2.41,'n':6.75,'o':7.51,'p':1.93,'q':0.10,'r':5.99,'s':6.33,'t':9.06,'u':2.76,'v':0.98,'w':2.36,'x':0.15,'y':1.97,'z':0.07}

for c in string.punctuation+string.digits+string.whitespace:
    expectedFrequencies[c] = 0
    
expectedFrequencies[' '] = 20


def score_text_for_english(text):
    # Exclude it if there are non-printable characters
    if not all([c in string.printable for c in text]):
        return 1000000

    d = collections.defaultdict(int)
    for c in text.lower():
        d[c] += 1
    total = float(len(text))
    frequencies = collections.defaultdict(float)
    # For each character, find actual proportion
    for char, count in d.iteritems():
        frequencies[char] = count / total * 120

    total_error = 0
    for char, expected in expectedFrequencies.iteritems():
        actual = frequencies[char]
        error = abs(expected - actual)
        squared = error ** 2
        total_error += squared

    return total_error

def is_probably_english(text):
    MAX_ERROR = 1000

    return score_text_for_english(text) < MAX_ERROR


def xor_bytes(binary_bytes, xor_key):
    xor_key_loop = itertools.cycle(xor_key)
    result = []
    for char, xor_char in zip(binary_bytes, xor_key_loop):
        num = ord(char)
        xor_byte = ord(xor_char)
        result.append(chr(xor_byte ^ num))
    return ''.join(result)


def xor_hex_string(hex_string, xor_key):
    binary_bytes = binascii.unhexlify(hex_string)
    result = xor_bytes(binary_bytes, xor_key)
    return binascii.hexlify(result)


def find_single_byte_xor_key_and_decode_hex_string(hex_string):
    bytes = binascii.unhexlify(hex_string)
    return find_single_byte_xor_key_and_decode_bytes(bytes)


def find_single_byte_xor_key_and_decode_bytes(bytes):
    for x in range(0,256):
        decoded_candidate = xor_bytes(bytes,[x])
        if is_probably_english(decoded_candidate):
            return decoded_candidate, x
    return None, None


def hamming_distance(bytes1, bytes2):
    """The number of bits different between the two sets of bytes"""
    total = 0
    for b1, b2 in zip(bytes1, bytes2):
        diff = ord(b1) ^ ord(b2)
        while diff:
            if diff & 1:
                total+=1
            diff >>= 1
    return total


def break_xor_with_key_length(ciphertext, key_length):
    full_key = []
    for starting_point in range(0, key_length):
        these_bytes = list(itertools.islice(ciphertext, starting_point, None, key_length))
        unused, key = find_single_byte_xor_key_and_decode_bytes(these_bytes)
        full_key.append(key)
        if key is None:
            print 'Unable to find key'
            return None, None
    discovered_key = ''.join(map(chr, full_key))
    return discovered_key, xor_bytes(ciphertext, full_key)