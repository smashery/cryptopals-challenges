import SimpleHTTPServer
import BaseHTTPServer
import re
import os
import binascii
import time
from hashes import *
hmac_key = os.urandom(16)

print binascii.hexlify(hmac_sha1(hmac_key, 'some_malicious_payload'))

class Hackable(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def do_GET(self):
        match = re.match(r'\/test\?file=(.*)\&signature=(.*)$', self.path)
        code=200
        if match is None:
            code=400
            message = 'Unknown Parameters'
        else:
            groups = match.groups()
            file = groups[0]
            sig = groups[1]
            if self.check_hmac_with_timing_leak(file, sig):
                code=200
                message = 'Valid File'
            else:
                code=500
                message='Invalid File'

        self.send_response(code)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(message)
        return

    def check_hmac_with_timing_leak(self, file, sig):
        hmac_calc = hmac_sha1(hmac_key, file)
        bin_sig = binascii.unhexlify(sig)
        if len(hmac_calc) != len(bin_sig):
            return False
        for user_sig_byte, server_sig_byte in zip(bin_sig, hmac_calc):
            if user_sig_byte != server_sig_byte:
                return False
            time.sleep(0.002)
        return True

def run_while_true(server_class=BaseHTTPServer.HTTPServer,
                   handler_class=Hackable):
    """
    This assumes that keep_running() is a function of no arguments which
    is tested initially and after each request.  If its return value
    is true, the server continues.
    """
    server_address = ('', 8000)
    httpd = server_class(server_address, handler_class)
    while True:
        httpd.handle_request()

run_while_true()

s = Hackable()