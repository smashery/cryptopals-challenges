from hashes import *
import binascii
import requests
import time
import numpy
import collections

server = 'localhost'
port = 8000
request_framework = '/test?file=%s&signature=%s'

message='some_malicious_payload'

def run_individual_timing_test(create_test_case_func, timed_func, x):
    case = create_test_case_func(x)
    now = time.clock()
    timed_func(case)
    return time.clock() - now

def do_another_run(timings, all_timings, create_test_case_func, timed_func):
    for x in range(0,256):
        duration = run_individual_timing_test(create_test_case_func, timed_func, x)
        timings[x].append(duration)
        all_timings.append(duration)


def guess_char_with_timing(create_test_case_func, timed_func, deviation_req):
    timings = collections.defaultdict([])
    all_timings = []
    finished = False
    while not finished:
        do_another_run(timings, all_timings, create_test_case_func, timed_func)
        arr = numpy.array(all_timings)
        overall_mean = numpy.mean(arr)
        stddev = numpy.std(arr)

        all_stddevs = {}

        for num, durations in timings.iteritems():
            arr = numpy.array(durations)
            mean_duration = numpy.mean(arr)
            dev = mean_duration - overall_mean
            # Calculate the number of standard deviations this datapoint is away
            num_stddevs = dev / stddev
            all_stddevs[num] = num_stddevs

        high_enough_stddev = list(filter(lambda k,v:v>=deviation_req, all_stddevs.iteritems()))
        if len(high_enough_stddev) == 1:
            return high_enough_stddev[0]


def run_timing_test(req, repeats):
    now = time.clock()
    for x in range(0, repeats):
        requests.get(req)
    return (time.clock() - now) / repeats

def determine_valid_mac_using_timing_attack(server, port, request_func, message):
    signature_length = 20
    signature_length_hex_chars = signature_length * 2
    # 20-byte signature
    unknown_chars='0'*signature_length_hex_chars
    known_chars = ''
    path = request_func(message, '1234')
    ping = run_timing_test('http://%s:%d/%s' % (server, port, path), 10)
    for x in range(0,signature_length):
        # For each byte
        unknown_chars = unknown_chars[2:]
        # If it fails on our char, it'll return straight away
        # But if it succeeds, it'll take a little while longer
        # We estimate 50ms, plus the ping
        expected_success_duration = ping + 0.05 * (x + 1)
        for possible_byte in range(0,256):
            hex_guess = binascii.hexlify(chr(possible_byte))
            guess = known_chars + hex_guess + unknown_chars
            assert len(guess) == signature_length_hex_chars
            path = request_func(message, guess)
            duration = run_timing_test('http://%s:%d%s' % (server, port, path), 2)
            if duration > expected_success_duration:
                # Probably correct
                known_chars += hex_guess
                break
        if possible_byte == 256:
            # Failed to find it
            assert False
    assert len(known_chars) == signature_length_hex_chars
    return known_chars


print determine_valid_mac_using_timing_attack(server, port, lambda f, s:request_framework % (f, s), message)