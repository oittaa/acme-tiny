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
    from urllib.request import urlopen, Request  # Python 3
    from urllib.error import HTTPError
except ImportError:
    from urllib2 import urlopen, HTTPError, Request  # Python 2

# DEFAULT_CA = "https://acme-staging-v02.api.letsencrypt.org/directory"
DEFAULT_CA = "https://acme-v02.api.letsencrypt.org/directory"

# helper function to base64 encode for jose spec
def _b64(data):
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

# helper function for openssl subprocess
def _openssl(command, options, communicate=None):
    openssl = subprocess.Popen(["openssl", command] + options, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = openssl.communicate(communicate)
    if openssl.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))
    return out

# helper function to parse domains from CSR
def _domains_from_csr(csr):
    csr_dump = _openssl("req", ["-in", csr, "-noout", "-text"]).decode("utf-8")
    domains = []
    common_name = re.search(r"Subject:.*? CN\s?=\s?([^\s,;/]+)", csr_dump)
    if common_name is not None:
        domains.append(common_name.group(1))
    subject_alt_names = re.search(r"X509v3 Subject Alternative Name: \n +([^\n]+)\n",
                                  csr_dump, re.MULTILINE|re.DOTALL)
    if subject_alt_names is not None:
        for san in subject_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                domains.append(san[4:])
    return domains

class ACMETiny(object):
    """ACMETiny implements a minimal client for the IETF Automatic Certificate
    Management Environment (ACME) protocol"""

    def __init__(self, account_key, acme_dir, ca=None, logger=None):
        if logger is None:
            log_format = '%(asctime)s - %(levelname)s - %(message)s'
            logging.basicConfig(format=log_format)
            logger = logging.getLogger(__name__)
            logger.setLevel(logging.INFO)
        self.account_key, self.acme_dir, self.log = account_key, acme_dir, logger
        resp = urlopen(ca or DEFAULT_CA)
        self.directory = json.loads(resp.read().decode('utf-8'))
        self.nonce = resp.headers.get('Replay-Nonce')
        self.account = {'kid': None, 'header': None, 'thumbprint': None}

    # helper function for rate limited queries
    def _urlopen_retry(self, url, retry_type, error_message):
        while True:
            self.log.debug("Fetching: %s", url)
            try:
                resp = urlopen(url)
                result = json.loads(resp.read().decode('utf-8'))
            except HTTPError as err:
                raise ValueError("Error fetching url: {0} {1} {2}".format(
                    url, err.code, json.loads(err.read().decode('utf-8'))))
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
    def _send_signed_request(self, url, payload, return_codes, error_message):
        self.log.debug("Signed request url: %s", url)
        self.log.debug("Signed request payload: %s", payload)
        payload = _b64(json.dumps(payload).encode('utf-8'))
        while True:
            protected = copy.deepcopy(self.account['header'])
            if url not in [self.directory['newAccount'], self.directory['revokeCert']]:
                del protected['jwk']
                protected['kid'] = self.account['kid']
            if self.nonce is None:
                self.log.debug("Nonce from newNonce resource: %s", self.directory['newNonce'])
                resp = urlopen(self.directory['newNonce'])
                self.nonce = resp.headers.get('Replay-Nonce')
            protected['nonce'] = re.sub(r"[^A-Za-z0-9_\-]", "", self.nonce)
            protected['url'] = url
            protected = _b64(json.dumps(protected).encode('utf-8'))
            sig = _b64(_openssl("dgst", ["-sha256", "-sign", self.account_key],
                                communicate="{0}.{1}".format(protected, payload).encode("utf-8")))
            data = json.dumps({"protected": protected, "payload": payload,
                               "signature": sig}).encode('utf-8')

            try:
                resp = urlopen(Request(url, data, {'Content-Type':'application/jose+json'}))
                code, result = resp.getcode(), resp.read().decode('utf-8')
                headers, message = resp.info(), return_codes[code]
                if headers.get('Content-Type') and 'json' in headers.get('Content-Type'):
                    result = json.loads(result)
                self.nonce = headers.get('Replay-Nonce')
                break
            except HTTPError as err:
                code, result, headers = err.code, json.loads(err.read().decode('utf-8')), err.info()
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

    # helper funtion to check that the well-known file is in place
    def _well_known_check(self, wellknown_url, wellknown_path, keyauthorization):
        try:
            resp = urlopen(wellknown_url)
            resp_data = resp.read().decode('utf-8').strip()
            assert resp_data == keyauthorization
            self.log.debug("Found token from %s", wellknown_url)
        except (IOError, AssertionError):
            error_message = "Wrote file to {0}, but couldn't download {1}"
            raise ValueError(error_message.format(wellknown_path, wellknown_url))

    # helper function to make authorization requests
    def _authz(self, url, skip_well_known_check):
        self.log.debug("Authz: %s", url)
        try:
            resp = urlopen(url)
            resp_data = json.loads(resp.read().decode('utf-8'))
        except HTTPError as err:
            error_message = "Error getting authz: {0} {1}"
            raise ValueError(error_message.format(err.code, json.loads(err.read().decode('utf-8'))))
        domain = resp_data['identifier']['value']
        self.log.info("Verifying %s...", domain)

        # make the challenge file
        challenge = [c for c in resp_data['challenges'] if c['type'] == "http-01"][0]
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
        keyauthorization = "{0}.{1}".format(token, self.account['thumbprint'])
        wellknown_path = os.path.join(self.acme_dir, token)
        with open(wellknown_path, "w") as wellknown_file:
            wellknown_file.write(keyauthorization)
        try:
            if not skip_well_known_check:
                wellknown_url = "http://{0}/.well-known/acme-challenge/{1}".format(domain, token)
                self._well_known_check(wellknown_url, wellknown_path, keyauthorization)
            # notify that the challenge is met
            error_message = "Error triggering challenge: {code} {result}"
            self._send_signed_request(challenge['url'], {},
                                      {200: "Challenge sent..."}, error_message)
            self._urlopen_retry(challenge['url'], 'pending', "Challenge did not pass: {result}")
            self.log.info("%s verified!", domain)
        finally:
            os.remove(wellknown_path)

    def parse_account_key(self):
        """Parse account key to get public key."""
        self.log.info("Parsing account key...")
        result = _openssl("rsa", ["-in", self.account_key, "-noout", "-text"])
        pub_hex, pub_exp = re.search(
            r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
            result.decode('utf-8'), re.MULTILINE | re.DOTALL).groups()
        pub_exp = "{0:x}".format(int(pub_exp))
        pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
        header = {
            "alg": "RS256",
            "jwk": {
                "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
                "kty": "RSA",
                "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8")))
            }
        }
        accountkey_json = json.dumps(header['jwk'], sort_keys=True, separators=(',', ':'))
        self.account['thumbprint'] = _b64(hashlib.sha256(accountkey_json.encode('utf-8')).digest())
        self.account['header'] = header

    def register_account(self):
        """Register the account and obtain Key ID."""
        self.log.info("Registering account...")
        payload = {"termsOfServiceAgreed": True}
        return_codes = {201: "Registered!", 200: "Already registered!"}
        error_message = "Error registering: {code} {result}"
        _result, headers = self._send_signed_request(self.directory['newAccount'], payload,
                                                     return_codes, error_message)
        self.account['kid'] = headers['Location']
        self.log.debug("Key ID: %s", self.account['kid'])

    def get_certificate(self, csr, skip_well_known_check=False):
        """Get signed certificate from CSR."""
        if self.account['header'] is None:
            self.parse_account_key()
        if self.account['kid'] is None:
            self.register_account()

        self.log.debug("Creating new order from %s", csr)
        self.log.info("Parsing CSR...")
        domains = _domains_from_csr(csr)
        self.log.info("Found domains: %s", "{0}".format(", ".join(domains)))
        payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}
        return_codes = {201: "Success!"}
        error_message = "Error requesting order: {code} {result}"
        self.log.info("Sending newOrder request...")
        result, headers = self._send_signed_request(self.directory['newOrder'], payload,
                                                    return_codes, error_message)
        order_url = headers['Location']
        for auth_url in result['authorizations']:
            self._authz(auth_url, skip_well_known_check)
        payload = {"csr": _b64(_openssl("req", ["-in", csr, "-outform", "DER"]))}
        return_codes = {200: "Success!"}
        error_message = "Error POSTing to finalize URL: {code} {result}"
        self.log.info("POSTing CSR to finalize URL...")
        self._send_signed_request(result['finalize'], payload, return_codes, error_message)
        result = self._urlopen_retry(order_url, 'processing', "Order isn't valid: {result}")
        self.log.debug("Downloading certificate: %s", result['certificate'])
        return urlopen(result['certificate']).read().decode('utf-8')

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
    parser.add_argument("--skip-well-known-check", action="store_true",
                        help="skip the local http check of .well-known/acme-challenge/")

    args = parser.parse_args(argv)

    acme = ACMETiny(args.account_key, args.acme_dir, ca=args.ca)
    acme.log.setLevel(args.quiet or acme.log.level)
    certificate = acme.get_certificate(args.csr, args.skip_well_known_check)
    with open(args.output, 'w') if args.output else sys.stdout as output:
        output.write(certificate)

if __name__ == "__main__":  # pragma: no cover
    main(sys.argv[1:])
