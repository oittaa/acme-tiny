#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""This script automates the process of getting a signed TLS certificate from
Let's Encrypt using the ACME v2 protocol. It will need to be run on your
server and have access to your private account key, so PLEASE READ THROUGH IT!
It won't take long."""

import base64
import binascii
import copy
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import textwrap
import time

try:
    from urllib.request import urlopen  # Python 3
    from urllib.error import HTTPError
except ImportError:
    from urllib2 import urlopen, HTTPError  # Python 2

DEFAULT_CA = "https://acme-staging-v02.api.letsencrypt.org/directory"
# DEFAULT_CA = "https://acme-v02.api.letsencrypt.org/directory"

# helper function to base64 encode for jose spec
def _b64(data):
    return base64.urlsafe_b64encode(data).decode('utf8').rstrip('=')

# helper function for openssl subprocess
def _openssl(command, options, communicate=None):
    openssl = subprocess.Popen(["openssl", command] + options, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = openssl.communicate(communicate)
    if openssl.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))
    return out


class ACMETiny(object):
    """ACMETiny implements a minimal client for the IETF Automatic Certificate
    Management Environment (ACME) protocol"""

    def __init__(self, account_key, csr, acme_dir, ca=None):
        self.paths = {"account_key": account_key, "csr": csr, "acme_dir": acme_dir}
        self.paths['acme_ca'] = ca or DEFAULT_CA
        self.kid = self.header = self.thumbprint = self.certificate = self.nonce = None
        logger = logging.getLogger(__name__)
        logger_handler = logging.StreamHandler()
        logger_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(logger_handler)
        logger.setLevel(logging.INFO)
        self.log = logger

    # helper function for rate limited queries
    def _urlopen_retry(self, url, retry_type, error_message):
        while True:
            self.log.debug("Fetching: %s", url)
            try:
                resp = urlopen(url)
                result = json.loads(resp.read().decode('utf8'))
            except HTTPError as err:
                raise ValueError("Error fetching url: {0} {1} {2}".format(
                    url, err.code, json.loads(err.read().decode('utf8'))))
            if result['status'] == retry_type:
                self._retry_after_sleep(resp.info())
            elif result['status'] == 'valid':
                return result
            else:
                raise ValueError(error_message.format(result=result))

    # helper function for waiting 'Retry-After' amount from headers
    def _retry_after_sleep(self, headers):
        retry_after = headers.get('Retry-After')
        if isinstance(retry_after, (str)) and retry_after.isdigit():
            retry_after = int(retry_after)
        else:
            retry_after = 2  # by default wait 2 seconds
        self.log.debug("Retrying in %d seconds...", retry_after)
        time.sleep(retry_after)

    # helper function to make signed requests
    def _send_signed_request(self, url_or_key, payload, return_codes, error_message):
        self.log.debug("Signed request url or key: %s", url_or_key)
        self.log.debug("Signed request payload: %s", payload)
        payload = _b64(json.dumps(payload).encode('utf8'))
        while True:
            protected = copy.deepcopy(self.header)
            resp = urlopen(self.paths['acme_ca'])
            result = json.loads(resp.read().decode('utf8'))
            if url_or_key in result:
                url = result[url_or_key]  # Use the URL from the /directory response
            else:
                url = url_or_key
            if url_or_key not in ['newAccount', 'revokeCert']:
                del protected['jwk']
                protected['kid'] = self.kid
            if self.nonce is None:
                if resp.headers.get('Replay-Nonce') is None:
                    self.log.debug("Nonce from newNonce resource: %s", result['newNonce'])
                    resp = urlopen(result['newNonce'])
                self.nonce = resp.headers.get('Replay-Nonce')
            protected['nonce'] = re.sub(r"[^A-Za-z0-9_\-]", "", self.nonce)
            protected['url'] = url
            protected = _b64(json.dumps(protected).encode('utf8'))
            sig = _b64(_openssl("dgst", ["-sha256", "-sign", self.paths['account_key']],
                                communicate="{0}.{1}".format(protected, payload).encode("utf8")))
            data = json.dumps({"protected": protected, "payload": payload, "signature": sig})

            try:
                resp = urlopen(url, data.encode('utf8'))
                code, result = resp.getcode(), resp.read().decode('utf8')
                headers, message = resp.info(), return_codes[code]
                if headers.get('Content-Type') and 'json' in headers.get('Content-Type'):
                    result = json.loads(result)
                self.nonce = headers.get('Replay-Nonce')
                break
            except HTTPError as err:
                code, result, headers = err.code, json.loads(err.read().decode('utf8')), err.info()
                self.nonce = headers.get('Replay-Nonce')
                if code == 400 and result.get('type') == 'urn:ietf:params:acme:error:badNonce':
                    self.log.warning("badNonce: retrying...")
                    continue
                if result.get('type') == 'urn:ietf:params:acme:error:rateLimited':
                    self.log.warning("rateLimited: retrying...")
                    self._retry_after_sleep(headers)
                    continue
                raise ValueError(error_message.format(code=code, result=result))
            except KeyError:
                raise ValueError(error_message.format(code=code, result=result))
        if message is not None:
            self.log.info(message)
        return result, headers

    # helper function to make authorization requests
    def _authz(self, url):
        self.log.debug("Authz: %s", url)
        try:
            resp = urlopen(url)
            resp_data = json.loads(resp.read().decode('utf8'))
        except HTTPError as err:
            error_message = "Error getting authz: {0} {1}"
            raise ValueError(error_message.format(err.code, json.loads(err.read().decode('utf8'))))
        domain = resp_data['identifier']['value']
        self.log.info("Verifying %s...", domain)

        # make the challenge file
        challenge = [c for c in resp_data['challenges'] if c['type'] == "http-01"][0]
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
        keyauthorization = "{0}.{1}".format(token, self.thumbprint)
        wellknown_path = os.path.join(self.paths['acme_dir'], token)
        with open(wellknown_path, "w") as wellknown_file:
            wellknown_file.write(keyauthorization)

        # check that the file is in place
        wellknown_url = "http://{0}/.well-known/acme-challenge/{1}".format(domain, token)
        try:
            resp = urlopen(wellknown_url)
            resp_data = resp.read().decode('utf8').strip()
            assert resp_data == keyauthorization
        except (IOError, AssertionError):
            os.remove(wellknown_path)
            error_message = "Wrote file to {0}, but couldn't download {1}"
            raise ValueError(error_message.format(wellknown_path, wellknown_url))

        # notify that the challenge is met
        payload = {"keyAuthorization": keyauthorization}
        self._send_signed_request(challenge['url'], payload, {200: "Challenge sent..."},
                                  "Error triggering challenge: {code} {result}")
        self._urlopen_retry(challenge['url'], 'pending', "Challenge did not pass: {result}")
        self.log.info("%s verified!", domain)
        os.remove(wellknown_path)

    def parse_account_key(self):
        """Parse account key to get public key and thumbprint."""
        self.log.info("Parsing account key...")
        result = _openssl("rsa", ["-in", self.paths['account_key'], "-noout", "-text"])
        pub_hex, pub_exp = re.search(
            r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
            result.decode('utf8'), re.MULTILINE | re.DOTALL).groups()
        pub_exp = "{0:x}".format(int(pub_exp))
        pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
        self.header = {
            "alg": "RS256",
            "jwk": {
                "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
                "kty": "RSA",
                "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8")))
            }
        }
        accountkey_json = json.dumps(self.header['jwk'], sort_keys=True, separators=(',', ':'))
        self.thumbprint = _b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())

    def register_account(self):
        """Register the account and obtain Key ID."""
        self.log.info("Registering account...")
        payload = {"termsOfServiceAgreed": True}
        return_codes = {201: "Registered!", 200: "Already registered!"}
        error_message = "Error registering: {code} {result}"
        _result, headers = self._send_signed_request("newAccount", payload,
                                                     return_codes, error_message)
        self.kid = headers['Location']
        self.log.debug("Key ID: %s", self.kid)

    def get_certificate(self):
        """Get signed certificate."""
        if self.thumbprint is None or self.header is None:
            self.parse_account_key()
        if self.kid is None:
            self.register_account()

        self.log.debug("Creating new order from %s", self.paths['csr'])
        # find domains
        self.log.info("Parsing CSR...")
        csr_dump = _openssl("req", ["-in", self.paths['csr'], "-noout", "-text"]).decode("utf8")
        domains = []
        common_name = re.search(r"Subject:.*? CN\s?=\s?([^\s,;/]+)", csr_dump)
        if common_name is not None:
            domains.append({"type": "dns", "value": common_name.group(1)})
        subject_alt_names = re.search(r"X509v3 Subject Alternative Name: \n +([^\n]+)\n",
                                      csr_dump, re.MULTILINE|re.DOTALL)
        if subject_alt_names is not None:
            for san in subject_alt_names.group(1).split(", "):
                if san.startswith("DNS:"):
                    domains.append({"type": "dns", "value": san[4:]})
        payload = {"identifiers": domains}
        return_codes = {201: "Success!"}
        error_message = "Error requesting order: {code} {result}"
        self.log.info("Sending newOrder request...")
        result, headers = self._send_signed_request("newOrder", payload,
                                                    return_codes, error_message)

        order_url = headers['Location']
        for auth_url in result['authorizations']:
            self._authz(auth_url)

        self.log.debug("Checking order to get finalize URL...")
        resp = urlopen(order_url)
        result = json.loads(resp.read().decode('utf8'))
        payload = {"csr": _b64(_openssl("req", ["-in", self.paths['csr'], "-outform", "DER"]))}
        return_codes = {200: "Success!"}
        error_message = "Error POSTing to finalize URL: {code} {result}"
        self.log.info("POSTing CSR to finalize URL...")
        self._send_signed_request(result['finalize'], payload, return_codes, error_message)
        result = self._urlopen_retry(order_url, 'processing', "Order isn't valid: {result}")
        self.log.debug("Downloading certificate: %s", result['certificate'])
        self.certificate = urlopen(result['certificate']).read().decode('utf8')
        self.log.info("Certificate signed!")


def main(argv):
    """Parse command line arguments and feed them to ACMETiny."""
    import argparse
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            This script automates the process of getting a signed TLS certificate from
            Let's Encrypt using the ACME v2 protocol. It will need to be run on your
            server and have access to your private account key, so PLEASE READ THROUGH IT!
            It won't take long.

            ===Example Usage===
            python acme_tiny.py --account-key ./account.key --csr ./domain.csr --acme-dir /var/www/challenges/ --output ./certificate.pem
            ===================

            ===Example Crontab Renewal (once per month)===
            0 0 1 * * python /path/to/acme_tiny.py --account-key /path/to/account.key --csr /path/to/domain.csr --acme-dir /var/www/challenges/ --output /path/to/certificate.pem 2>> /var/log/acme_tiny.log
            ==============================================
            """)
    )
    parser.add_argument("--account-key", required=True,
                        help="path to your Let's Encrypt account private key")
    parser.add_argument("--csr", required=True,
                        help="path to your certificate signing request")
    parser.add_argument("--acme-dir", required=True,
                        help="path to the .well-known/acme-challenge/ directory")
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR,
                        help="suppress output except for errors")
    parser.add_argument("--ca", default=None,
                        help="certificate authority's directory object, default is Let's Encrypt")
    parser.add_argument("--output", "-o", metavar="FILE", default=None,
                        help="output file, default is standard output")

    args = parser.parse_args(argv)

    acme = ACMETiny(args.account_key, args.csr, args.acme_dir, ca=args.ca)
    acme.log.setLevel(args.quiet or acme.log.level)
    acme.get_certificate()
    with open(args.output, 'w') if args.output else sys.stdout as output:
        output.write(acme.certificate)

if __name__ == "__main__":  # pragma: no cover
    main(sys.argv[1:])
