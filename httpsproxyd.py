#!/usr/local/bin/python3
import ssl
import re
import os
import sys
import signal
import argparse
import requests  # this dependency needs to be installed manually
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from threading import Lock

HSPD_EXIT_SUCCESS = 0
HSPD_EXIT_FAILURE = 1
HSPD_HOST = '0.0.0.0'
HSPD_PORT = 4443
HSPD_SERVER_CERTFILE_PATH = './server.pem'  # has to contain private key, first the cert, then the key
HSPD_LOG_FILE = '/var/log/httpsproxyd/httpsproxyd.log'
HSPD_PID_FILE = '/var/run/httpsproxyd.pid'
HSPD_ALLOWED_URL_REGEXPS = [
    re.compile('https://someurl[a-z0-9_-]+\.example\.com', re.I),
]
hspd_stderr_lock = Lock()
hspd_stderr = sys.stderr
hspd_pid_file = HSPD_PID_FILE


def log(log_item):
    with hspd_stderr_lock:
        try:
            hspd_stderr.write(str(log_item) + '\n')
            hspd_stderr.flush()
        except Exception:
            pass


class RequestHandler(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def retrieve_url(self, url, headers=None):
        resp = requests.get(url, headers=headers)
        return resp

    def header_ok_to_rewrite(self, hdr):
        lower_key = hdr.lower()
        return lower_key.startswith('accept') or lower_key in ['cache-control', 'user-agent']

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
            if key.lower() not in ['server', 'date', 'connection']:
                self.send_header(key, resp.headers[key])
        self.end_headers()
        self.wfile.write(resp.content)

    def url_is_allowed(self, url):
        if url is not None:
            for url_regexp in HSPD_ALLOWED_URL_REGEXPS:
                if url_regexp.match(url) is not None:
                    return True
        return False

    def log_message(self, format, *args):
        log(format % args)

    def do_GET(self):
        try:
            self.process_request()
        except Exception as e:
            log(e)

    def process_request(self):
        log(self.requestline)
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
                if 'url' in params and self.url_is_allowed(params['url'][0]):
                    hdrs = self.prepare_headers(self.headers)
                    resp = self.retrieve_url(params['url'][0] + self.path, hdrs)
                    self.write_response(resp)
                else:
                    self.send_error(404)
            else:
                self.send_error(404)
        else:
            self.send_error(404)


def daemonize():
    pid = os.fork()
    if pid > 0:
        sys.exit(HSPD_EXIT_SUCCESS)
    elif pid < 0:
        log('fork failed: ' + str(pid))
        sys.exit(HSPD_EXIT_FAILURE)
    os.chdir('/')
    os.setsid()
    os.umask(0)
    sys.stdin.close()
    sys.stdout.close()


def parse_arguments():
    parser = argparse.ArgumentParser(description='Runs a daemon acting as HTTPS proxy.')
    parser.add_argument('-c', dest='cert_path', nargs=1, default=[HSPD_SERVER_CERTFILE_PATH], help='absolute path to certificate file')
    parser.add_argument('--logfile', dest='log_file', nargs=1, default=[HSPD_LOG_FILE], help='absolute path to log file')
    parser.add_argument('--pidfile', dest='pid_file', nargs=1, default=[HSPD_PID_FILE], help='absolute path to PID file')
    parser.add_argument('-p', dest='port', nargs=1, default=[HSPD_PORT], help='port number to listen on')
    parser.add_argument('-l', dest='host', nargs=1, default=[HSPD_HOST], help='host/IP address to listen on')
    args = parser.parse_args()
    return (args.cert_path[0], args.log_file[0], args.pid_file[0], args.port[0], args.host[0])


def create_log_file(log_file_path):
    try:
        with hspd_stderr_lock:
            global hspd_stderr
            hspd_stderr = open(log_file_path, 'a')
            sys.stderr.close()
        log('PID: ' + str(os.getpid()))
    except Exception as e:
        log('error opening log file: %s: %s' % (log_file_path, str(e)))


def create_pid_file(pid_file_path):
    try:
        with open(pid_file_path, 'w') as pid_file:
            pid_file.write(str(os.getpid()))
            global hspd_pid_file
            hspd_pid_file = pid_file_path
    except Exception as e:
        log('error opening PID file: %s: %s' % (pid_file_path, str(e)))


def remove_pid_file(pid_file_path):
    try:
        os.remove(pid_file_path)
    except Exception as e:
        log('error removing PID file: %s: %s' % (pid_file_path, str(e)))


def exit_failure():
    remove_pid_file(hspd_pid_file)
    sys.exit(HSPD_EXIT_FAILURE)


def handle_signal(signal_number, stack):
    remove_pid_file(hspd_pid_file)
    sys.exit(HSPD_EXIT_SUCCESS)


if __name__ == '__main__':
    (cert_file, log_file, pid_file, port, host) = parse_arguments()
    daemonize()
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    create_log_file(log_file)
    create_pid_file(pid_file)
    try:
        httpd = HTTPServer((host, int(port)), RequestHandler)
        httpd.socket = ssl.wrap_socket(httpd.socket, certfile=cert_file, server_side=True)
        httpd.serve_forever()
    except FileNotFoundError as e:
        log('certificate error: ' + str(e))
        exit_failure()
    except ssl.SSLError as e:
        log('certificate SSL error: ' + str(e))
        exit_failure()
    except Exception as e:
        log('unknown error: ' + str(e))
        exit_failure()
    remove_pid_file(hspd_pid_file)
