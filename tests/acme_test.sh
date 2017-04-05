#!/bin/sh

testAcmeTiny() {
	python acme_tiny.py --account-key ${testDir}/account.key --csr ${testDir}/domain.csr --acme-dir ${webDir}/.well-known/acme-challenge --ca https://acme-staging.api.letsencrypt.org --output ${testDir}/signed.crt
	rtrn=$?
	assertTrue 'expecting return code of 0 (true)' ${rtrn}
}

testCertificate() {
	openssl x509 -in ${testDir}/signed.crt -text -noout
	rtrn=$?
	assertTrue 'expecting return code of 0 (true)' ${rtrn}
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

	ngrok/ngrok http 8080 --log stdout --log-format logfmt --log-level debug > ${testDir}/tmp.log &
	sleep 2
	TMP_URL="$(grep -Eo "Hostname:[a-z0-9]+.ngrok.io" ${testDir}/tmp.log | head -1 | cut -d':' -f2)"
	if [ -z "${TMP_URL}" ]; then
		echo "Couldn't get an url from ngrok, tests can't continue."
		exit 1
	fi
	# Run python webserver in .acme-challenges directory to serve challenge responses
	webDir=${testDir}/webserver
	mkdir -p ${webDir}/.well-known/acme-challenge
	(
		cd ${webDir}
		python -m SimpleHTTPServer 8080 > /dev/null 2> /dev/null
	) &
	openssl genrsa 4096 > ${testDir}/account.key
	openssl genrsa 4096 > ${testDir}/domain.key
	openssl req -new -sha256 -key ${testDir}/domain.key -subj "/CN=${TMP_URL}" > ${testDir}/domain.csr
}

# load shunit2
. shunit2-source/2.1.6/src/shunit2
