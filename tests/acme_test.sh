#!/bin/sh

testAcmeTiny() {
	python acme_tiny.py --account-key ${testDir}/account.key --csr ${testDir}/domain.csr --acme-dir ~/challenges/ --ca https://acme-staging.api.letsencrypt.org --output ${testDir}/signed.crt
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
	MYIP=$(dig +short myip.opendns.com @resolver1.opendns.com)
	if [ -z "$MYIP" ]
	then
		echo "Couldn't resolve IP address"
		exit 1
	fi
	MYHOST=$(dig +short -x $MYIP @resolver1.opendns.com)

	if [ -n "$MYHOST" ]
	then
		MYHOST=$(echo $MYHOST | sed 's/\.$//')
	else
		echo "Couldn't resolve hostname"
		exit 1
	fi

	openssl genrsa 4096 > ${testDir}/account.key
	openssl genrsa 4096 > ${testDir}/domain.key
	openssl req -new -sha256 -key ${testDir}/domain.key -subj "/CN=$MYHOST" > ${testDir}/domain.csr
}

# load shunit2
. shunit2-source/2.1.6/src/shunit2
