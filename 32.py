import requests
from timing_attack import *

server = '127.0.0.1'
port = 8000
request_framework = 'http://%s:%d' % (server, port) + '/test?file=%s&signature=%s'

message='some_malicious_payload'

result = determine_valid_mac_using_timing_attack(lambda f, s:request_framework % (f, s), message)
print 'Found signature: %s' % (result,)
r = requests.get(request_framework % (message, result))
if r.status_code == 200:
    print 'Success'
else:
    print r.status_code