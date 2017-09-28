#!/usr/local/bin/python3

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import requests, ssl, re
#requests dependency needs to be installed manually

HOST = '0.0.0.0'
PORT = 4443
SERVER_CERTFILE_PATH = './server.pem' # has to contain private key, first the cert, then the key
ALLOWED_URL_REGEXPS = [
    re.compile('https://someurl[a-z0-9_-]+\.com',re.I),
]

class RequestHandler(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def retrieve_url(self, url, headers=None):
        resp = requests.get(url, headers=headers)
        return resp

    def header_ok_to_rewrite(self, hdr):
        lower_key = hdr.lower()
        return lower_key.startswith('accept') or lower_key in ['cache-control','user-agent']

    def prepare_headers(self, headers):
        hdrs = {}
        for key in headers:
            if self.header_ok_to_rewrite(key):
                hdrs[key] = headers[key]
        return hdrs

    def write_response(self, resp):
        if resp.status_code < 400:
            self.send_response(resp.status_code)
        else:
            self.send_error(resp.status_code)
        for key in resp.headers:
            if key.lower() not in ['server','date','connection']:
                self.send_header(key, resp.headers[key])
        self.end_headers()
        self.wfile.write(resp.content)

    def url_is_allowed(self, url):
        if url is not None:
            for url_regexp in ALLOWED_URL_REGEXPS:
                if url_regexp.match(url) is not None:
                    return True
        return False

    def do_GET(self):
        print(self.requestline)
        parsed = urlparse(self.path)
        params = parse_qs(parsed[4])
        if params is not None:
            if 'url' in params and self.url_is_allowed(params['url'][0]):
                hdrs = self.prepare_headers(self.headers)
                resp = self.retrieve_url(params['url'][0], hdrs)
                self.write_response(resp)
            elif 'Referer' in self.headers:
                parsed = urlparse(self.headers['Referer'])
                params = parse_qs(parsed[4])
                if self.url_is_allowed(params['url'][0]):
                    hdrs = self.prepare_headers(self.headers)
                    resp = self.retrieve_url(params['url'][0] + self.path, hdrs)
                    self.write_response(resp)
                else:
                    self.send_error(404)
            else:
                self.send_error(404)
        else:
            self.send_error(404)

httpd = HTTPServer((HOST, PORT), RequestHandler)
httpd.socket = ssl.wrap_socket (httpd.socket, certfile=SERVER_CERTFILE_PATH, server_side=True)
httpd.serve_forever()
