#!/bin/sh

testAcmeTinyV1SingleDomain() {
	python acme_tiny.py --account-key ${testDir}/account.key --csr ${testDir}/domain1.csr --acme-dir ${webDir}/.well-known/acme-challenge --ca https://acme-staging.api.letsencrypt.org --output ${testDir}/v1signed1.crt
	rtrn=$?
	assertTrue 'expecting return code of 0 (true)' ${rtrn}
}

testAcmeTinyV2SingleDomain() {
	python acme_tiny_v2.py --account-key ${testDir}/account.key --csr ${testDir}/domain1.csr --acme-dir ${webDir}/.well-known/acme-challenge --ca https://acme-staging-v02.api.letsencrypt.org/directory --output ${testDir}/v2signed1.crt
	rtrn=$?
	assertTrue 'expecting return code of 0 (true)' ${rtrn}
}

testCertificateSingleDomain() {
	openssl crl2pkcs7 -nocrl -certfile ${testDir}/v1signed1.crt | openssl pkcs7 -print_certs -text -noout | grep -Fq "DNS:${tmpURL1}"
	rtrn=$?
	assertTrue 'v1 expecting return code of 0 (true)' ${rtrn}
	openssl crl2pkcs7 -nocrl -certfile ${testDir}/v2signed1.crt | openssl pkcs7 -print_certs -text -noout | grep -Fq "DNS:${tmpURL1}"
	rtrn=$?
	assertTrue 'v2 expecting return code of 0 (true)' ${rtrn}
}

testCertificateChainLength() {
	rtrn=$(openssl crl2pkcs7 -nocrl -certfile ${testDir}/v1signed1.crt | openssl pkcs7 -print_certs -text -noout | grep -c '^Certificate:')
	assertTrue 'v1 expecting at least two certificates in chain' "[ ${rtrn} -ge 2 ]"
#	rtrn=$(openssl crl2pkcs7 -nocrl -certfile ${testDir}/v2signed1.crt | openssl pkcs7 -print_certs -text -noout | grep -c '^Certificate:')
#	assertTrue 'v2 expecting at least two certificates in chain' "[ ${rtrn} -ge 2 ]"
}

testAcmeTinyV1MultipleDomains() {
	python acme_tiny.py --account-key ${testDir}/account.key --csr ${testDir}/domain2.csr --acme-dir ${webDir}/.well-known/acme-challenge --ca https://acme-staging.api.letsencrypt.org --output ${testDir}/v1signed2.crt
	rtrn=$?
	assertTrue 'expecting return code of 0 (true)' ${rtrn}
}

testAcmeTinyV2MultipleDomains() {
	python acme_tiny_v2.py --account-key ${testDir}/account.key --csr ${testDir}/domain2.csr --acme-dir ${webDir}/.well-known/acme-challenge --ca https://acme-staging-v02.api.letsencrypt.org/directory --output ${testDir}/v2signed2.crt
	rtrn=$?
	assertTrue 'expecting return code of 0 (true)' ${rtrn}
}

testCertificateMultipleDomains() {
	openssl crl2pkcs7 -nocrl -certfile ${testDir}/v1signed2.crt | openssl pkcs7 -print_certs -text -noout | grep -F "DNS:${tmpURL2}" | grep -Fq "DNS:${tmpURL3}"
	rtrn=$?
	assertTrue 'v1 expecting return code of 0 (true)' ${rtrn}
	openssl crl2pkcs7 -nocrl -certfile ${testDir}/v2signed2.crt | openssl pkcs7 -print_certs -text -noout | grep -F "DNS:${tmpURL2}" | grep -Fq "DNS:${tmpURL3}"
	rtrn=$?
	assertTrue 'v2 expecting return code of 0 (true)' ${rtrn}
}

oneTimeSetUp()
{
	testDir="${SHUNIT_TMPDIR}/acme"
	mkdir ${testDir} || exit 1

	# If not found (should be cached in travis) download ngrok
	if [ ! -e "ngrok/ngrok" ]; then
		(
			mkdir -p ngrok
			cd ngrok
			wget https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-amd64.zip -O ngrok.zip
			unzip ngrok.zip ngrok
			chmod +x ngrok
		)
	fi

	ngrok/ngrok http 8080 --log stdout --log-format logfmt --log-level debug > ${testDir}/tmp1.log &
	ngrok/ngrok http 8080 --log stdout --log-format logfmt --log-level debug > ${testDir}/tmp2.log &
	ngrok/ngrok http 8080 --log stdout --log-format logfmt --log-level debug > ${testDir}/tmp3.log &
	sleep 2
	tmpURL1="$(grep -Eo "Hostname:[a-z0-9]+.ngrok.io" ${testDir}/tmp1.log | head -1 | cut -d':' -f2)"
	tmpURL2="$(grep -Eo "Hostname:[a-z0-9]+.ngrok.io" ${testDir}/tmp2.log | head -1 | cut -d':' -f2)"
	tmpURL3="$(grep -Eo "Hostname:[a-z0-9]+.ngrok.io" ${testDir}/tmp3.log | head -1 | cut -d':' -f2)"
	if [ -z "${tmpURL1}" ] || [ -z "${tmpURL2}" ] || [ -z "${tmpURL3}" ]; then
		echo "Couldn't get an url from ngrok, tests can't continue."
		exit 1
	fi
	# Run python webserver to serve challenge responses
	webDir=${testDir}/webserver
	mkdir -p ${webDir}/.well-known/acme-challenge
	(
		cd ${webDir}
		if [ "3.0" = "$(printf "${TRAVIS_PYTHON_VERSION}\n3.0" | sort -V | head -n 1)" ]; then
			python -m http.server 8080 > /dev/null 2> /dev/null
		else
			python -m SimpleHTTPServer 8080 > /dev/null 2> /dev/null
		fi
	) &
	openssl genrsa 4096 > ${testDir}/account.key
	openssl genrsa 4096 > ${testDir}/domain.key
	openssl req -new -sha256 -key ${testDir}/domain.key -subj "/" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:${tmpURL1}")) > ${testDir}/domain1.csr
	openssl req -new -sha256 -key ${testDir}/domain.key -subj "/" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:${tmpURL2},DNS:${tmpURL3}")) > ${testDir}/domain2.csr
}

# load shunit2
. shunit2-source/2.1.6/src/shunit2
