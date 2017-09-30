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

### Certificate
The certificate must be in PEM format and the file must first contain the certificate and the private key in that order.

### Using httpsproxy
Edit the `httpsproxyd.py` file and edit the `HSPD_ALLOWED_URL_REGEXPS` array, putting in which URLs need the proxying be restricted to.

There is no need running it from `root` so don't.
