# httpsproxy - an extremely simple and tiny HTTPS proxy daemon.

### Requirements:
- Python 3.4+ - https://www.python.org
- requests - https://pypi.python.org/pypi/requests

### Running:
    usage: httpsproxyd.py [-h] [-c CERT_PATH] [-l LOG_FILE] [-p PID_FILE]


    Runs a daemon acting as HTTPS proxy.

    optional arguments:
      -h, --help    show this help message and exit
      -c CERT_PATH  absolute path to certificate file
      -l LOG_FILE   absolute path to log file
      -p PID_FILE   absolute path to PID file

### Certificate:
The certificate must be in PEM format and the file must first contain the certificate and the private key in that order.

### Using httpsproxy:
Edit the `httpsproxyd.py` file and edit the `HSPD_ALLOWED_URL_REGEXPS` array, putting in which URLs need the proxying be restricted to.

The proxying is done by adding a query parameter to the URL of the proxy server. Assuming the httpsproxy listens on `https://localhost:4443`, to proxy to a URL of let's say `https://example.com` a proxy URL should look like this: `https://localhost:4443/?url=https://example.com`. This only works if it is allowed by by `HSPD_ALLOWED_URL_REGEXPS`.

There is no need running it from `root` so don't.
