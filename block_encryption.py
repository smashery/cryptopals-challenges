import itertools
import re
from decode_xor import *
import grequests

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


def decrypt_ecb_byte_by_byte(func, ignore_initial_blocks=0, oracle_func=None,oracle_block_num=None):
    """
    If our input text is inserted at the start of some ECB text, we can figure out the last char
    :param func: The function that encrypts text
    """
    block_size = determine_block_size_of_cipher(func)
    total_empty_length = len(func(''))
    num_blocks = total_empty_length / block_size
    print '%d blocks to decrypt. Ignoring %d blocks' % (num_blocks, ignore_initial_blocks)
    previous_block = ''
    known_plaintext = ''
    if oracle_func is not None:
        validate_oracle(func, ignore_initial_blocks, oracle_func, oracle_block_num, block_size)
    for block_num in range(ignore_initial_blocks, num_blocks):
        block_plaintext = decrypt_nth_ecb_block(func, block_num, previous_block, block_size, ignore_initial_blocks, oracle_func, oracle_block_num + block_num - ignore_initial_blocks)
        known_plaintext += block_plaintext
        previous_block = block_plaintext
    print known_plaintext
    
def validate_oracle(encrypt_func, ignore_initial_blocks, oracle_func, oracle_block_num, block_size):
    encrypted = encrypt_func('A' * block_size)
    encrypt_block = encrypted[ignore_initial_blocks * block_size : (ignore_initial_blocks + 1) * block_size]
    oracled = oracle_func('A' * block_size)
    oracle_block = oracled[oracle_block_num * block_size : (oracle_block_num + 1) * block_size]
    assert encrypt_block == oracle_block


def decrypt_nth_ecb_block(encrypt_func, block_num, previous_block, block_size, ignore_initial_blocks, oracle_func=None, oracle_block_num=None):
    if oracle_func is None:
        oracle_func = encrypt_func
        oracle_block_num = block_num
    care_about_unicode = True
    print 'Block size is %d' % block_size
    print 'Block num is %d, %d' % (block_num, oracle_block_num)
    ignore_chars = block_size * ignore_initial_blocks
    known_chars = ''
    total_empty_length = len(encrypt_func(''))
    num_blocks = total_empty_length / block_size
    is_last_block = block_num == num_blocks - 1
    while len(known_chars) != block_size:
        junk = 'A' * (block_size - len(known_chars) - 1)
        block_input_minus_one = junk + previous_block + known_chars
        lookup = {}
        for next_char in range(0, 128):
            input_plaintext = block_input_minus_one + chr(next_char)
            if next_char > 127 and care_about_unicode:
                input_plaintext += '\x41' # Add an arbitrary character to increase the chance that it'll be a valid UTF-16 character on the other side?
            length = len(input_plaintext) + ignore_chars
            ciphertext = oracle_func(input_plaintext)
            last_test_block = ciphertext[oracle_block_num * block_size:(oracle_block_num + 1) * block_size]
            if lookup.has_key(last_test_block):
              print 'duplicate: %d, %d' % (lookup[last_test_block], next_char)
              pass
            lookup[last_test_block] = next_char
        #print len(lookup)
        #assert(len(lookup) == 256) # Should have 256 different options
        ciphertext = encrypt_func(junk)
        nth_block = ciphertext[block_num * block_size:(block_num + 1) * block_size]
        next_char = chr(lookup[nth_block])
        print 'next char is %s (%d)' % (next_char, ord(next_char))
        known_chars += next_char
        if is_last_block and len(ciphertext) == total_empty_length:
            # We've crossed a block boundary - end here before we ask for a char too far
            return known_chars

    return known_chars


def nth_block(text, block_num, block_size):
    return text[block_num * block_size : (block_num + 1) * block_size]


def get_text_injection_location(encrypt_func):
    block_size = determine_block_size_of_cipher(encrypt_func)
    print 'Block size is %d' % block_size
    unstable = list(find_unstable_blocks(encrypt_func, block_size))
    print 'Unstable blocks: %s' % unstable
    one = encrypt_func('A')
    two = encrypt_func('B')
    num_blocks = len(one) / block_size
    for block_num in range(0, num_blocks):
        if block_num in unstable:
            continue
        if nth_block(one, block_num, block_size) != nth_block(two, block_num, block_size):
            break

    # So we've now deduced that our input starts in the nth block
    input_block_with_all_a = nth_block(encrypt_func('A' * (2 * block_size)), block_num + 1, block_size)
    input = 'A' * block_size + 'B'
    while (nth_block(encrypt_func(input), block_num + 1, block_size) != input_block_with_all_a):
        input = 'A' + input
    # At this point, the 'B' has just moved out of the next block: the next block is all A's. 
    b_locn = input.index('B')
    
    # So subtract that many A's, and that's how many characters we need to align with a boundary
    num_chars = b_locn - block_size

    return block_num, num_chars, block_size


def decrypt_ecb_byte_by_byte_with_unknown_number_of_bytes_at_start(encrypt_func, oracle_func, oracle_block_num):
    block_num, num_chars, block_size = get_text_injection_location(encrypt_func)
    print 'Injection after %d blocks, %d characters = %d' % (block_num, num_chars, block_num * block_size + num_chars)
    # Pad out our function so that we align with a block boundary:
    decrypt_ecb_byte_by_byte(lambda text: encrypt_func('X' * num_chars + text), block_num + 1, oracle_func, oracle_block_num)


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


def insert_text_with_cbc_bitflip_i_have_no_idea_what_this_does(func, desired_text):
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

def insert_text_with_cbc_bitflip(oracle_func, bool_func, desired_text, block_size):
    '''
    Encrypt an entire message with a CBC padding oracle attack.
    This requires access to the IV
    To do this, we create what is essentially a rubbish ciphertext, which will likely not even
    decrypt to anything valid. We run our padding oracle attack against it to see what the Nth
    block (starting at the end) does decrypt to, and then we use a CBC bit flipping attack to
    xor the (N-1)th block to make the last block what we want it to be.
    We repeat this process for N-1, until we are modifying the IV.
    Dang! It's super effective.
    '''
    print('Padding text')
    desired_text = pad_pkcs7(desired_text, block_size)
    
    # What the ciphertext is doesn't matter - we'll just "decrypt" it anyway.
    # Something will produce correct padding and we'll be able to figure it out
    fake_char = 'A'

    all_blocks = list(chunks(desired_text, block_size))
    all_blocks.reverse()
    fake_ciphertext = fake_char * block_size
    result = ''
    encrypted_block = fake_ciphertext
    
    result += encrypted_block # We're just gonna fix this last block and roll with it
    for desired in all_blocks:
        IV = fake_ciphertext # Again, just a fake IV
        actual = decrypt_block(oracle_func, bool_func, IV, encrypted_block)
        difference = xor_bytes(actual, desired)
        encrypted_block = xor_bytes(difference, IV) # this will be "fixed" (i.e. no longer changed), and used for the next iteration of the loop
        result = encrypted_block + result

    return result


def has_valid_padding(oracle_func, block1, block2):
    ciphertext = block1 + block2
    return oracle_func(ciphertext)


def decrypt_cbc_using_padding_attack(ciphertext, oracle_func, bool_func, block_size_guess, skip_blocks=0):
    if len(ciphertext) % block_size_guess != 0:
        print 'Cannot be this block size. Ciphertext length was %d' % len(ciphertext)
    all_blocks = list(chunks(ciphertext, block_size_guess))
    prev_blocks = all_blocks[skip_blocks:]
    blocks = prev_blocks[1:]

    result = ''
    for p, b in zip(prev_blocks, blocks):
        result += decrypt_block(oracle_func, bool_func, p, b)

    return result


def decrypt_block(oracle_func, bool_func, previous_block, block):
    block_size = len(block)
    result_so_far = ''
    for char_num in range(0, block_size, 1):
        new_char = find_actual_char_value(oracle_func, bool_func, block, previous_block, block_size - 1 - char_num, result_so_far)
        print 'Got %s (%d)' % (new_char, ord(new_char))
        result_so_far = new_char + result_so_far
    print 'Decrypted block: %s (%s)' % (result_so_far, str(map(ord, result_so_far)))
    return result_so_far


def change_char(text, char_num, xor_key):
    cipher_char = text[char_num]
    prefix = text[:char_num]
    suffix = text[char_num + 1:]
    return prefix + xor_bytes(cipher_char, xor_key) + suffix

def find_actual_char_value(oracle_func, bool_func, block, previous_block, char_to_test, known_end_chars):
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

    requests = (oracle_func(change_char(previous_block, char_to_test, chr(x)) + block) for x in range(0,256))
    responses = None
    while responses == None:
        responses = grequests.map(requests, size=10)
        if responses == None:
            print('Request failed. Trying again')
    for x in range(0,256):
        if bool_func(responses[x]):
            good_values.append(x)

    if len(good_values) == 2:
        # Change the previous char and redo the test.
        # It doesn't matter what we xor it with. As long as it changes.
        with_prev_char_changed = change_char(previous_block, char_to_test - 1, 'X')
        for x in good_values:
            modified_again = change_char(with_prev_char_changed, char_to_test, chr(x))
            if has_valid_padding(oracle_func, modified_again, block):
                correct_value = x
                break
        else:
            raise Exception('Could not find good value out of %s' % (good_values))

    elif len(good_values) == 1:
        correct_value = good_values[0]
    else:
        assert False, 'Should always find one or two valid values. Has %d' % len(good_values)

    # The number we must have succeeded in coercing it to was number_to_coerce_to
    # The number we used to do this was good_values[0]. So we can xor to find the actual value
    result = chr(correct_value ^ number_to_coerce_to)
    return result

def find_unstable_blocks(encrypt_func, block_size):
    '''
    Blocks that change even with the same encryption. We shall ignore those in certain cases
    '''
    val1 = encrypt_func('A');
    val2 = encrypt_func('A');
    for i in range(0, len(val1), block_size):
        if val1[i:i+block_size] != val2[i:i+block_size]:
            yield i / block_size

def get_key_from_same_iv_as_key(encrypt_func, decrypt_func):
    block_size = 16
    ciphertext = encrypt_func('A'*3*block_size)
    chunked = chunks(ciphertext, block_size)
    chunk1 = chunked.next()
    new_ciphertext = chunk1 + '\x00' * block_size + chunk1
    try:
        decrypt_func(new_ciphertext)
    except InvalidMessageException, e:
        matches = re.match('Unprintable characters: (.*)$', e.message)
        plaintext = matches.groups()[0]
        chunked = chunks(plaintext, block_size)
        chunk1 = chunked.next()
        chunked.next()
        chunk3 = chunked.next()
        key = xor_bytes(chunk1, chunk3)
        return key
    return None