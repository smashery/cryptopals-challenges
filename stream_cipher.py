import itertools

from decode_xor import *

def decrypt_and_print_all_ciphertexts_with_stream(ciphertexts, bitstream_guess):
    max_len = max(map(len, ciphertexts))
    repeats = max_len / 10 + 1
    s = '   '
    for x in range(0,repeats):
        s += str(x) + ' ' * 9
    print s
    print '   ' + '0123456789' * repeats
    for i, ciphertext in enumerate(ciphertexts):
        result = ''
        for bitstream_char_guess, byte in zip(bitstream_guess, map(ord, ciphertext)):
            if bitstream_char_guess is None:
                result += '?'
            else:
                result += chr(byte ^ bitstream_char_guess)
        print "%02d" % i, result


def make_initial_guess_of_bitstream(ciphertexts):
    """
    Make a stab at a bitstream guess, assuming English plaintext, given
    multiple ciphertexts believed xor-encrypted with the same bitstream
    """
    chars_by_position = list(itertools.izip_longest(*ciphertexts))
    bitstream_guess = []
    for chars in chars_by_position:
        # Require at least 5 to guess
        if len(chars) > 5:
            # Let's make a hypothesis about what the bitstream value was:
            best = (None, 1e8)
            for hypothesis in range(0,256):
                resulting_chars = ''
                for char in chars:
                    if char is None:
                        break
                    orig_char = ord(char) ^ hypothesis
                    resulting_chars += chr(orig_char)
                score = score_text_for_english(resulting_chars)
                if score < best[1]:
                    best = (hypothesis, score)
            if best[1] < 500:
                bitstream_guess.append(best[0])
            else:
                bitstream_guess.append(None)
        else:
            bitstream_guess.append(None)
    return bitstream_guess


def coerce_bitstream_guess_with(ciphertexts, text_index, char_index, desired_char, bitstream_guess):
    """
    Change bitstream_guess to force ciphertexts[text_index][char_index] ^ bitstream_guess[char_index] == desired_char
    """
    ciphertext = ciphertexts[text_index]
    char = ciphertext[char_index]
    new_bitstream_guess = ord(char) ^ ord(desired_char)
    bitstream_guess[char_index] = new_bitstream_guess


def get_stream_text_injection_location(func):
    ciphertext1 = func('A')
    ciphertext2 = func('B')
    for i, (c1, c2) in enumerate(zip(ciphertext1, ciphertext2)):
        if c1 != c2:
            return i
    return None


def insert_text_into_ctr(func, desired_text):
    location = get_stream_text_injection_location(func)
    benign_text = 'A'*len(desired_text)
    ciphertext = func(benign_text)
    bits_to_overwrite = ciphertext[location:location+len(desired_text)]
    assert len(benign_text) == len(bits_to_overwrite) == len(desired_text)
    modified_ciphertext = ciphertext[:location] + \
                          xor_bytes(benign_text, xor_bytes(bits_to_overwrite, desired_text)) + \
                          ciphertext[location+len(desired_text):]
    return modified_ciphertext