from hashes import *
import binascii
import requests
import time
import numpy
import collections

server = '127.0.0.1'
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


def guess_char_with_timing(create_test_case_func, timed_func, std_deviation_clearance_required, min_repeats=2):
    next_check = 1000
    timings = collections.defaultdict(lambda:[])
    all_timings = []
    numbers_to_check = list(range(0,256))
    check_value = None

    # Do all but one of the minimum runs through initially
    for x in range(0, min_repeats-1):
        do_another_run(numbers_to_check, timings, all_timings, create_test_case_func, timed_func)

    while True:
        do_another_run(numbers_to_check, timings, all_timings, create_test_case_func, timed_func)
        arr = numpy.array(all_timings)
        overall_mean = numpy.mean(arr)
        stddev = numpy.std(arr)

        all_stddevs = {}

        best = (0, None)

        for num, durations in timings.iteritems():
            arr = numpy.array(durations)
            mean_duration = numpy.mean(arr)
            dev = mean_duration - overall_mean
            # Calculate the number of standard deviations this datapoint is away
            num_stddevs = dev / stddev
            all_stddevs[num] = num_stddevs
            if num_stddevs > best[0]:
                best = (num_stddevs, num)
        numbers_within_clearance_range = list(map(lambda x: x[0], filter(lambda i: i[1] > 0 and best[0] / i[1] < std_deviation_clearance_required, all_stddevs.iteritems())))
        if len(numbers_within_clearance_range) == 1: # Itself
            suspected_result = best[1]
            if check_value is not None and check_value == suspected_result:
                print 'Confirmed: %s' % binascii.hexlify(chr(suspected_result))
                return suspected_result
            else:
                # Run it another 10 times and make sure we're still above our threshold.
                # We don't want a single bad measurement to push us over the top
                print 'Next char may be 0x%02x; stddev=%f. Checking...' % (best[1], best[0])
                # Let's remove its old timings to avoid biasing the result with an outlier
                for t in timings[suspected_result]:
                    all_timings.remove(t)
                del timings[suspected_result]

                numbers_to_check = [suspected_result]*100
                check_value = suspected_result
        else:
            if check_value is not None:
                print "Hypothesis doesn't hold up under further investigation: stddev=%f" % all_stddevs[check_value]
            check_value = None
            if len(all_timings) > next_check:
                # The real one may have gotten unlucky. Let's redo everything
                print 'Too uncertain. Trying all possibilities again'
                numbers_to_check = range(0,256)
                next_check += 1000
            else:
                # Re-check those closest to the top (including the top itself)
                numbers_to_check = numbers_within_clearance_range
            assert len(numbers_to_check) > 0


def determine_valid_mac_using_timing_attack(request_func, message):
    repeat_test = 2
    signature_length = 20
    signature_length_hex_chars = signature_length * 2
    # 20-byte signature
    unknown_chars='0'*signature_length_hex_chars
    known_chars = ''
    for x in range(0,signature_length):
        print 'Finding byte %d...' % x
        # For each byte
        unknown_chars = unknown_chars[2:]
        # Run the test twice.
        # If it somehow gives the wrong answer the first time, the chance of it giving the same
        # wrong answer the second time is ludicrously low
        while True:
            results = []
            for x in range(0, repeat_test):
                results.append(guess_char_with_timing(lambda x: request_func(message, known_chars + binascii.hexlify(chr(x)) + unknown_chars), requests.get, 3))
            if all([c == results[0] for c in results]):
                char_num = results[0]
                break
            else:
                print 'Different answers on subsequent runs. Going again :-('
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