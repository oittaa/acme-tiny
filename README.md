# acme-tiny

This is a tiny, auditable script that you can throw on your server to issue
and renew [Let's Encrypt](https://letsencrypt.org/) certificates. Since it has
to be run on your server and have access to your private Let's Encrypt account
key, I tried to make it as tiny as possible (currently around 200 lines).
The only prerequisites are Python and OpenSSL.

**PLEASE READ THE SOURCE CODE! YOU MUST TRUST IT WITH YOUR PRIVATE KEYS!**

##Donate

If this script is useful to you, please donate to the EFF. I don't work there,
but they do fantastic work.

[https://eff.org/donate/](https://eff.org/donate/)

## How to use this script

If you already have a Let's Encrypt issued certificate and just want to renew,
you should only have to do Steps 3 and 6.

### Step 1: Create a Let's Encrypt account private key (if you haven't already)

You must have a public key registered with Let's Encrypt and sign your requests
with the corresponding private key. If you don't understand what I just said,
this script likely isn't for you! Please use the official Let's Encrypt
[client](https://github.com/letsencrypt/letsencrypt).

```sh
openssl genrsa 4096 > account.key
```

### Step 2: Create a certificate signing request (CSR) for your domains.

The ACME protocol (what Let's Encrypt uses) requires a CSR file to be submitted
to it, even for renewals. You can use the same CSR for multiple renewals. NOTE:
you can't use your account private key as your domain private key!

```sh
#generate a domain private key (if you haven't already)
openssl genrsa 4096 > domain.key
```

```sh
#for a single domain
openssl req -new -sha256 -key domain.key -subj "/CN=yoursite.com" > domain.csr

#for multiple domains (use this one if you want both www.yoursite.com and yoursite.com)
openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:yoursite.com,DNS:www.yoursite.com")) > domain.csr
```

### Step 3: Make your website host challenge files

You must prove you own the domains you want a certificate for, so Let's Encrypt
requires you host some files on them. This script will generate and write those
files in the folder you specify, so all you need to do is make sure that this
folder is served under the ".well-known/acme-challenge/" url path. NOTE: This
must be on port 80 (not port 443).

```sh
#make some challenge folder (modify to suit your needs)
mkdir -p /var/www/challenges/
```

```nginx
#example for nginx
server {
    listen 80;
    server_name yoursite.com www.yoursite.com;

    location /.well-known/acme-challenge/ {
        alias /var/www/challenges/;
        try_files $uri =404;
    }

    ...the rest of your config
}
```

```apache
#example for Apache 2.4
<VirtualHost *:80>
    ServerName yoursite.com
    ServerAlias www.yoursite.com

    Alias "/.well-known/acme-challenge" "/var/www/challenges"
    <Directory "/var/www/challenges">
        AllowOverride None
    </Directory>

    ...the rest of your config
</VirtualHost>
```

### Step 4: Get a signed certificate!

Now that you have setup your server and generated all the needed files, run this
script on your server with the permissions needed to write to the above folder
and read your private account key and CSR.

```sh
#run the script on your server
python acme_tiny.py --account-key ./account.key --csr ./domain.csr --acme-dir /var/www/challenges/ --output ./certificate.pem
```

### Step 5: Install the certificate

The signed https certificate that is output by this script can be used along
with your private key to run an https server. You need to include them in the
https settings in your web server's configuration. Here's an example on how to
configure an nginx server:

```sh
openssl dhparam -out dhparam.pem 4096
```

```nginx
server {
    listen 443;
    server_name yoursite.com www.yoursite.com;

    ssl on;
    ssl_certificate /path/to/certificate.pem;
    ssl_certificate_key /path/to/domain.key;
    ssl_session_timeout 5m;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA;
    ssl_session_cache shared:SSL:50m;
    ssl_dhparam /path/to/dhparam.pem;
    ssl_prefer_server_ciphers on;

    ...the rest of your config
}

server {
    listen 80;
    server_name yoursite.com www.yoursite.com;

    location /.well-known/acme-challenge/ {
        alias /var/www/challenges/;
        try_files $uri =404;
    }

    ...the rest of your config
}
```

```apache
#example for Apache 2.4
SSLStaplingCache shmcb:/var/run/ocsp(128000)
<VirtualHost *:443>
    ServerName yoursite.com
    ServerAlias www.yoursite.com

    SSLEngine On
    SSLProtocol all -SSLv2 -SSLv3
    SSLHonorCipherOrder on
    SSLUseStapling on
    SSLStaplingResponderTimeout 5
    SSLStaplingReturnResponderErrors off
    SSLCertificateKeyFile /path/to/domain.key
    SSLCertificateFile /path/to/certificate.pem
    SSLCipherSuite ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA
    #If you DON'T have Apache 2.4.8 or later and OpenSSL 1.0.2 or later, comment out the following line
    SSLOpenSSLConfCmd DHParameters /path/to/dhparam.pem

    ...the rest of your config
</VirtualHost>

<VirtualHost *:80>
    ServerName yoursite.com
    ServerAlias www.yoursite.com

    Alias "/.well-known/acme-challenge" "/var/www/challenges"
    <Directory "/var/www/challenges">
        AllowOverride None
    </Directory>

    ...the rest of your config
</VirtualHost>
```

### Step 6: Setup an auto-renew cronjob

Congrats! Your website is now using https! Unfortunately, Let's Encrypt
certificates only last for 90 days, so you need to renew them often. No worries!
It's automated! Just make a bash script and add it to your crontab (see below
for example script).

Example of a `renew_cert.sh`:
```sh
#!/bin/sh
set -e
TMPCRT=$(mktemp)
python /path/to/acme_tiny.py --account-key /path/to/account.key --csr /path/to/domain.csr --acme-dir /var/www/challenges/ --output "${TMPCRT}"
mv "${TMPCRT}" /path/to/certificate.pem
sudo service nginx reload
```

```
#example line in your crontab (runs every monday between 02:00 and 03:00)
0 2 * * 1 perl -le 'sleep rand 3600' && /path/to/renew_cert.sh 2>> /var/log/acme_tiny.log
```

## Permissions

The biggest problem you'll likely come across while setting up and running this
script is permissions. You want to limit access to your account private key and
challenge web folder as much as possible. I'd recommend creating a user
specifically for handling this script, the account private key, and the
challenge folder. Then add the ability for that user to write to your installed
certificate file (e.g. `/path/to/certificate.pem`) and reload your webserver.
That way, the cron script will do its thing, overwrite your old certificate,
and reload your webserver without having permission to do anything else. For
example you could allow user `acme` to reload nginx and Apache 2 by editing
`/etc/sudeors`.

```
acme    ALL=(ALL) NOPASSWD: service nginx reload, service apache2 reload
```

**BE SURE TO:**
* Backup your account private key (e.g. `account.key`)
* Don't allow this script to be able to read your domain private key!
* Don't allow this script to be run as root!

## Feedback/Contributing

This project has a very, very limited scope and codebase. I'm happy to receive
bug reports and pull requests, but please don't add any new features. This
script must stay short to ensure it can be easily audited by anyone who wants
to run it.

If you want to add features for your own setup to make things easier for you,
please do! It's open source, so feel free to fork it and modify as necessary.
