from hashes import *
import binascii
import requests
import time
import numpy
import collections

server = 'localhost'
port = 8000
request_framework = 'http://%s:%d' % (server, port) + '/test?file=%s&signature=%s'

message='some_malicious_payload'

# I'm trying to do it statistically here, where we repeat tests until we have confidence.


def run_individual_timing_test(create_test_case_func, timed_func, x):
    case = create_test_case_func(x)
    now = time.clock()
    timed_func(case)
    return time.clock() - now


def do_another_run(numbers_to_check, timings, all_timings, create_test_case_func, timed_func):
    for x in numbers_to_check:
        duration = run_individual_timing_test(create_test_case_func, timed_func, x)
        timings[x].append(duration)
        all_timings.append(duration)


def guess_char_with_timing(create_test_case_func, timed_func, std_deviations_req, minimum_full_repeats=1, consideration_stddev=None):
    if consideration_stddev is None:
        consideration_stddev = std_deviations_req / 2
    timings = collections.defaultdict(lambda:[])
    all_timings = []
    finished = False
    numbers_to_check = list(range(0,256))
    check_value = None

    # Do all but one of the runs in this initial loop, then we'll kick off the main loop
    for x in range(0, minimum_full_repeats-1):
        do_another_run(numbers_to_check, timings, all_timings, create_test_case_func, timed_func)

    while not finished:
        do_another_run(numbers_to_check, timings, all_timings, create_test_case_func, timed_func)
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

        high_enough_stddev = list(filter(lambda i:i[1] >= std_deviations_req, all_stddevs.iteritems()))
        if len(high_enough_stddev) == 1:
            suspected_result = high_enough_stddev[0]
            if check_value is not None and check_value == suspected_result[0]:
                print 'Confirmed: %s' % binascii.hexlify(chr(suspected_result[0]))
                return suspected_result[0]
            else:
                # Run it another 10 times and make sure we're still above our threshold.
                # We don't want a single bad measurement to push us over the top
                print 'We believe the answer is 0x%02x; stddev=%f. Checking...' % suspected_result
                # Let's remove its old timings to avoid biasing the result with an outlier
                for t in timings[suspected_result[0]]:
                    all_timings.remove(t)
                del timings[suspected_result[0]]
                numbers_to_check = [suspected_result[0]]*10
                check_value = suspected_result[0]
        else:
            if check_value is not None:
                print "Hypothesis doesn't hold up under further investigation: stddev=%f" % all_stddevs[check_value]
            check_value = None
            # Just re-check the numbers which are within half the required number of std deviations
            numbers_to_check = list(map(lambda x:x[0], filter(lambda i:i[1] >= consideration_stddev, all_stddevs.iteritems())))
            if len(numbers_to_check) == 0:
                print 'All numbers under required stddev. Testing them all again.'
                numbers_to_check = range(0,256)


def determine_valid_mac_using_timing_attack(request_func, message):
    signature_length = 20
    signature_length_hex_chars = signature_length * 2
    # 20-byte signature
    unknown_chars='0'*signature_length_hex_chars
    known_chars = ''
    for x in range(0,signature_length):
        print 'Finding byte %d...' % x
        # For each byte
        unknown_chars = unknown_chars[2:]
        char_num = guess_char_with_timing(lambda x: request_func(message, known_chars + binascii.hexlify(chr(x)) + unknown_chars), requests.get, 1.3, 1, 1)
        known_chars += binascii.hexlify(chr(char_num))
    assert len(known_chars) == signature_length_hex_chars
    return known_chars


result = determine_valid_mac_using_timing_attack(lambda f, s:request_framework % (f, s), message)
print 'Found signature: %s' % (result,)
r = requests.get(request_framework % (message, result))
if r.status_code == 200:
    print 'Success'
else:
    print r.status_code