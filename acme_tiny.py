#!/usr/bin/env python
import argparse, subprocess, json, os, sys, base64, binascii, time, hashlib, re, copy, textwrap, logging
INSECURE_PYTHON = False
if sys.version_info[0] < 3:
    from urllib2 import urlopen
    if (2, 7, 9) > sys.version_info: INSECURE_PYTHON = True
else:
    from urllib.request import urlopen
    if (3, 4, 3) > sys.version_info: INSECURE_PYTHON = True

#DEFAULT_CA = "https://acme-staging.api.letsencrypt.org"
DEFAULT_CA = "https://acme-v01.api.letsencrypt.org"

LOGGER = logging.getLogger(__name__)
LOGGER_HANDLER = logging.StreamHandler()
LOGGER_HANDLER.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
LOGGER.addHandler(LOGGER_HANDLER)
LOGGER.setLevel(logging.INFO)

def get_crt(account_key, csr, acme_dir, log=LOGGER, CA=DEFAULT_CA):
    # helper function base64 encode for jose spec
    def _b64(b):
        return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")

    # helper function for openssl subprocess
    def _openssl(command, options, communicate=None):
        openssl = subprocess.Popen(["openssl", command] + options,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = openssl.communicate(communicate)
        if openssl.returncode != 0:
            raise IOError("OpenSSL Error: {0}".format(err))
        return out

    if INSECURE_PYTHON: log.warning("Your Python version is insecure! It can't verify server certificates! Please consider upgrading your Python interpreter. Secure minimum versions are 2.7.9 and 3.4.3 for Python 2 and Python 3 respectively. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-9365")

    # parse account key to get public key
    log.info("Parsing account key...")
    pub_hex, pub_exp = re.search(
        r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
        _openssl("rsa", ["-in", account_key, "-noout", "-text"]).decode('utf8'), re.MULTILINE|re.DOTALL).groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    header = {
        "alg": "RS256",
        "jwk": {
            "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
            "kty": "RSA",
            "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
        },
    }
    accountkey_json = json.dumps(header['jwk'], sort_keys=True, separators=(',', ':'))
    thumbprint = _b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())

    # helper function make signed requests
    def _send_signed_request(url_or_key, payload):
        payload64 = _b64(json.dumps(payload).encode('utf8'))
        protected = copy.deepcopy(header)
        directory_request = urlopen(CA + "/directory")
        directory_data = json.loads(directory_request.read().decode('utf8'))
        if url_or_key in directory_data:
            # Use the URL from the /directory response
            url = directory_data[url_or_key]
        else:
            url = url_or_key
        protected["nonce"] = directory_request.headers['Replay-Nonce']
        protected64 = _b64(json.dumps(protected).encode('utf8'))
        data = json.dumps({
            "header": header, "protected": protected64, "payload": payload64,
            "signature": _b64(_openssl("dgst", ["-sha256", "-sign", account_key],
                communicate="{0}.{1}".format(protected64, payload64).encode("utf8")))
        })
        try:
            resp = urlopen(url, data.encode('utf8'))
            return resp.getcode(), resp.read(), resp.info()
        except IOError as e:
            return getattr(e, "code", None), getattr(e, "read", e.__str__)(), None

    # find domains
    log.info("Parsing CSR...")
    csr_dump = _openssl("req", ["-in", csr, "-noout", "-text"]).decode("utf8")
    domains = set([])
    common_name = re.search(r"Subject:.*? CN\s?=\s?([^\s,;/]+)", csr_dump)
    if common_name is not None:
        domains.add(common_name.group(1))
    subject_alt_names = re.search(r"X509v3 Subject Alternative Name: \n +([^\n]+)\n", csr_dump, re.MULTILINE|re.DOTALL)
    if subject_alt_names is not None:
        for san in subject_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                domains.add(san[4:])

    # get the certificate domains and expiration
    log.info("Registering account...")
    code, result, headers = _send_signed_request("new-reg", {
        "resource": "new-reg",
        "agreement": json.loads(urlopen(CA + "/directory").read().decode('utf8'))['meta']['terms-of-service'],
    })
    if code == 201:
        log.info("Registered!")
    elif code == 409:
        log.info("Already registered!")
    else:
        raise ValueError("Error registering: {0} {1}".format(code, result))

    # verify each domain
    for domain in domains:
        log.info("Verifying {0}...".format(domain))

        # get new challenge
        code, result, headers = _send_signed_request("new-authz", {
            "resource": "new-authz",
            "identifier": {"type": "dns", "value": domain},
        })
        if code != 201:
            raise ValueError("Error requesting challenges: {0} {1}".format(code, result))

        # make the challenge file
        challenge = [c for c in json.loads(result.decode('utf8'))['challenges'] if c['type'] == "http-01" or c['status'] == "valid"][0]
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
        keyauthorization = "{0}.{1}".format(token, thumbprint)
        wellknown_path = os.path.join(acme_dir, token)
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
            raise ValueError("Wrote file to {0}, but couldn't download {1}".format(
                wellknown_path, wellknown_url))

        # notify challenge are met
        code, result, headers = _send_signed_request(challenge['uri'], {
            "resource": "challenge",
            "keyAuthorization": keyauthorization,
        })
        if code != 202:
            raise ValueError("Error triggering challenge: {0} {1}".format(code, result))

        # wait for challenge to be verified
        while True:
            try:
                resp = urlopen(challenge['uri'])
                challenge_status = json.loads(resp.read().decode('utf8'))
            except IOError as e:
                raise ValueError("Error checking challenge: {0} {1}".format(
                    e.code, json.loads(e.read().decode('utf8'))))
            if challenge_status['status'] == "pending":
                time.sleep(2)
            elif challenge_status['status'] == "valid":
                log.info("{0} verified!".format(domain))
                os.remove(wellknown_path)
                break
            else:
                raise ValueError("{0} challenge did not pass: {1}".format(
                    domain, challenge_status))

    # get the new certificate
    log.info("Signing certificate...")
    code, result, headers = _send_signed_request("new-cert", {
        "resource": "new-cert",
        "csr": _b64(_openssl("req", ["-in", csr, "-outform", "DER"])),
    })
    if code != 201:
        raise ValueError("Error signing certificate: {0} {1}".format(code, result))

    # get certificate chain
    cert_chain = [result]
    link = headers.get('Link')
    while link:
        url = re.search('^<(http[^>]+)>;rel="up"$', link)
        if url:
            url = url.group(1)
        else:
            break
        if len(cert_chain) > 10:
            raise ValueError("Recursion limit reached. Didn't get {0}".format(url))
        try:
            resp = urlopen(url)
            link = resp.info().get('Link')
            result = resp.read()
            cert_chain.append(result)
        except IOError as e:
            raise ValueError("Couldn't download certificate {0}, {1} {2}".format(
                url, e.code, e.read()))

    # return signed certificate!
    log.info("Certificate signed!")
    return ''.join("""-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n""".format(
        "\n".join(textwrap.wrap(base64.b64encode(cert).decode('utf8'), 64))) for cert in cert_chain)

def main(argv):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            This script automates the process of getting a signed TLS certificate from
            Let's Encrypt using the ACME protocol. It will need to be run on your server
            and have access to your private account key, so PLEASE READ THROUGH IT! It's
            only ~200 lines, so it won't take long.

            ===Example Usage===
            python acme_tiny.py --account-key ./account.key --csr ./domain.csr --acme-dir /usr/share/nginx/html/.well-known/acme-challenge/ --output signed.crt
            ===================

            ===Example Crontab Renewal (once per month)===
            0 0 1 * * python /path/to/acme_tiny.py --account-key /path/to/account.key --csr /path/to/domain.csr --acme-dir /usr/share/nginx/html/.well-known/acme-challenge/ --output /path/to/signed.crt 2>> /var/log/acme_tiny.log
            ==============================================
            """)
    )
    parser.add_argument("--account-key", required=True, help="path to your Let's Encrypt account private key")
    parser.add_argument("--csr", required=True, help="path to your certificate signing request")
    parser.add_argument("--acme-dir", required=True, help="path to the .well-known/acme-challenge/ directory")
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="suppress output except for errors")
    parser.add_argument("--ca", default=DEFAULT_CA, help="certificate authority, default is Let's Encrypt")
    parser.add_argument("--output", "-o", metavar="FILE", default=None, help="output file, default is standard output")

    args = parser.parse_args(argv)
    LOGGER.setLevel(args.quiet or LOGGER.level)
    signed_crt = get_crt(args.account_key, args.csr, args.acme_dir, log=LOGGER, CA=args.ca)
    with open(args.output, 'w') if args.output else sys.stdout as f:
        f.write(signed_crt)

if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])
