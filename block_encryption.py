import itertools


def pad_pkcs7(text, block_size):
    remainder = len(text) % block_size
    pad_required = block_size - remainder
    return text + ''.join(itertools.repeat(chr(pad_required), pad_required))


def chunks(text, n):
    """Yield successive n-sized chunks from text."""
    for i in range(0, len(text), n):
        yield text[i:i + n]


def looks_like_ecb_aes(line, chunk_size=16):
    line_set = set()
    for chunk in chunks(line, chunk_size):
        if chunk in line_set:
            return True
    return False


def guess_aes_mode(block_size, offset=1):
    text = 'A' * 200
    ciphertext = encrypt_with_random_key(text)
    c1 = ciphertext[block_size*offset:block_size*(offset+1)]
    c2 = ciphertext[block_size*(offset+1):block_size*(offset+2)]
    if c1 == c2:
        return AES.MODE_ECB
    return AES.MODE_CBC


def determine_block_size_of_cipher(func):
    # TODO: This could be binary searched
    x = 1
    prev = -1
    while True:
        ciphertext = func('A'*x)
        l = len(ciphertext)
        if l != prev and prev != -1:
            return l - prev
        prev = l
        x+=1


def decrypt_ecb_byte_by_byte(func, ignore_initial_blocks=0):
    """
    If our input text is inserted at the start of some ECB text, we can figure out the last char
    :param func: The function that encrypts text
    """
    block_size = determine_block_size_of_cipher(func)
    total_empty_length = len(func(''))
    num_blocks = total_empty_length / block_size
    previous_block = ''
    known_plaintext = ''
    for block_num in range(ignore_initial_blocks, num_blocks):
        block_plaintext = decrypt_nth_ecb_block(func, block_num, previous_block, block_size, ignore_initial_blocks)
        known_plaintext += block_plaintext
        previous_block = block_plaintext
    print known_plaintext


def decrypt_nth_ecb_block(func, block_num, previous_block, block_size, ignore_initial_blocks):
    ignore_chars = block_size * ignore_initial_blocks
    known_chars = ''
    total_empty_length = len(func(''))
    num_blocks = total_empty_length / block_size
    is_last_block = block_num == num_blocks - 1
    while len(known_chars) != block_size:
        junk = 'A' * (block_size - len(known_chars) - 1)
        block_input_minus_one = junk + previous_block + known_chars
        lookup = {}
        for next_char in range(0, 256):
            input_plaintext = block_input_minus_one + chr(next_char)
            length = len(input_plaintext) + ignore_chars
            ciphertext = func(input_plaintext)
            last_test_block = ciphertext[length-block_size:length]
            lookup[last_test_block] = next_char

        assert(len(lookup) == 256) # Should have 256 different options
        ciphertext = func(junk)
        nth_block = ciphertext[block_num * block_size:(block_num + 1) * block_size]
        next_char = chr(lookup[nth_block])
        known_chars += next_char
        if is_last_block and len(ciphertext) == total_empty_length:
            # We've crossed a block boundary - end here before we ask for a char too far
            return known_chars

    return known_chars


def nth_block(text, block_num, block_size):
    return text[block_num * block_size : (block_num + 1) * block_size]


def get_text_injection_location(encrypt_func):
    block_size = determine_block_size_of_cipher(encrypt_func)
    one = encrypt_func('A')
    two = encrypt_func('B')
    num_blocks = len(one) / block_size
    for block_num in range(0, num_blocks):
        if nth_block(one, block_num, block_size) != nth_block(two, block_num, block_size):
            break

    # So we've now deduced that our input starts in the nth block
    input_block_with_all_a = nth_block(encrypt_func('A' * block_size), block_num, block_size)
    for num_chars in range(block_size - 1, -1, -1):
        test_ciphertext = encrypt_func('A' * num_chars + 'B')
        if nth_block(test_ciphertext, block_num, block_size) != input_block_with_all_a:
            # The 'B' has now moved into our input block. So we need to prefix (num_chars + 1) characters
            # in order to end up starting on a block boundary
            # The exception being that if (num_chars + 1) is equal to block_size, then we don't need any
            # prefix at all
            num_chars += 1
            num_chars %= block_size
            break

    return block_num, num_chars, block_size


def decrypt_ecb_byte_by_byte_with_unknown_number_of_bytes_at_start(encrypt_func):
    block_num, num_chars, block_size = get_text_injection_location(func)
    decrypt_ecb_byte_by_byte(lambda text: encrypt_func('X' * num_chars + text), block_num + 1)


class InvalidMessageException(Exception):
    def __init__(self, message, *args, **kwargs):
        super(InvalidMessageException, self).__init__(*args, **kwargs)
        self.message = message


def strip_pkcs7_padding(text):
    last_char = text[-1]
    num_chars = ord(last_char)
    if num_chars == 0:
        return None
    for x in range(0, num_chars):
        if ord(text[-x-1]) != num_chars:
            return None
    return text[0:len(text)-num_chars]


def insert_text_with_cbc_bitflip(func, desired_text):
    block_num, num_chars, block_size = get_text_injection_location(func)

    # TODO: Could pad this instead.
    # And maybe even do multiple blocks?
    assert(len(desired_text) == block_size)

    # Pad out the previous block
    plaintext = num_chars * 'A'
    # Add another two blocks of A's: one to xor the payload
    plaintext += 'A' * 2 * block_size
    ciphertext = encrypt_url(plaintext)
    payload_block_start = block_num*block_size
    payload_block_end = (block_num+1)*block_size
    pre_payload = ciphertext[:payload_block_start]
    payload_block = ciphertext[payload_block_start:payload_block_end]
    post_payload = ciphertext[payload_block_end:]

    # We know that the block is all A's. We need to make it desired_text:
    transform_required = xor_bytes(block_size * 'A', desired_text)

    payload_inserted = xor_bytes(payload_block, transform_required)
    return pre_payload + payload_inserted + post_payload


def insert_text_with_cbc_bitflip(func, desired_text):
    block_num, num_chars, block_size = get_text_injection_location(func)

    # TODO: Could pad this instead.
    # And maybe even do multiple blocks?
    assert(len(desired_text) == block_size)

    # Pad out the previous block
    plaintext = num_chars * 'A'
    # Add another two blocks of A's: one to xor the payload
    plaintext += 'A' * 2 * block_size
    ciphertext = encrypt_url(plaintext)
    payload_block_start = block_num*block_size
    payload_block_end = (block_num+1)*block_size
    pre_payload = ciphertext[:payload_block_start]
    payload_block = ciphertext[payload_block_start:payload_block_end]
    post_payload = ciphertext[payload_block_end:]

    # We know that the block is all A's. We need to make it desired_text:
    transform_required = xor_bytes(block_size * 'A', desired_text)

    payload_inserted = xor_bytes(payload_block, transform_required)
    return pre_payload + payload_inserted + post_payload


def has_valid_padding(ciphertext, iv):
    cipher = AES.AESCipher(global_key, mode=AES.MODE_CBC, IV=iv)
    plaintext = cipher.decrypt(ciphertext)
    return strip_pkcs7_padding(plaintext) is not None


def decrypt_cbc_using_padding_attack(func, block_size_guess):
    ciphertext, iv = func()
    if len(ciphertext) % block_size_guess != 0:
        print 'Cannot be this block size. Ciphertext length was %d' % len(ciphertext)
    blocks = list(chunks(ciphertext, block_size_guess))
    prev_blocks = [iv] + blocks

    result = ''
    for p, b in zip(prev_blocks, blocks):
        result += decrypt_block(b, p)

    return result


def decrypt_block(block, previous_block):
    block_size = len(block)
    result_so_far = ''
    for char_num in range(0, block_size, 1):
        new_char = find_actual_char_value(block, previous_block, block_size - 1 - char_num, result_so_far)
        result_so_far = new_char + result_so_far
    return result_so_far


def change_char(text, char_num, xor_key):
    cipher_char = text[char_num]
    prefix = text[:char_num]
    suffix = text[char_num + 1:]
    return prefix + xor_bytes(cipher_char, xor_key) + suffix


def find_actual_char_value(block, previous_block, char_to_test, known_end_chars):
    num_known_chars = len(known_end_chars)
    num_unknown_chars = len(block) - num_known_chars
    assert(len(block) == char_to_test + num_known_chars + 1), 'Mismatch in known_end_chars'
    good_values = []

    # Need to make the pkcs7 padding be correct
    number_to_coerce_to = num_known_chars + 1

    # Since we know some of the last chars, we can coerce them to the values we want them to be by xoring the
    # same position in the previous block
    replace_ending = xor_bytes(xor_bytes(known_end_chars, chr(number_to_coerce_to)), previous_block[num_unknown_chars:])
    previous_block = previous_block[:num_unknown_chars] + replace_ending

    for x in range(0,256):
        modified_block = change_char(previous_block, char_to_test, chr(x))
        if has_valid_padding(block, modified_block):
            good_values.append(x)

    if len(good_values) == 2:
        # Change the previous char and redo the test.
        # It doesn't matter what we xor it with. As long as it changes.
        with_prev_char_changed = change_char(previous_block, char_to_test - 1, 'X')
        for x in good_values:
            modified_again = change_char(with_prev_char_changed, char_to_test, chr(x))
            if has_valid_padding(block, modified_again):
                correct_value = x
                break

    elif len(good_values) == 1:
        correct_value = good_values[0]
    else:
        assert False, 'Should always find one or two valid values. Has %d' % len(good_values)

    # The number we must have succeeded in coercing it to was number_to_coerce_to
    # The number we used to do this was good_values[0]. So we can xor to find the actual value
    return chr(correct_value ^ number_to_coerce_to)
