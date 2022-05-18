#!/bin/bash

# This script can be used to generate a self-signed test-certificate for the fictional principal "Alice".
# The certificate is issued on the basis of a standard RSA key-pair.

### Set the openssl version to use.
openssl_bin="/usr/local/opt/openssl@1.1/bin/openssl"
account_name="alice"
priv_key_name="${account_name}.priv"
certificate_config_filename="${account_name}.cnf"
validity_days=1825 # Five years, so the tests won't fail too soon.

echo "Generating private RSA key"
$openssl_bin genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:4096 -pkeyopt rsa_keygen_pubexp:65537 -out ${priv_key_name}.rsakey
### Save the private key without password protection
$openssl_bin rsa -in ${priv_key_name}.rsakey -out ${priv_key_name}.nopass.rsakey

echo "Generating self-signed certificate..."
$openssl_bin req -outform PEM -out ${account_name}.pem -key ${priv_key_name}.nopass.rsakey -keyform PEM -x509 -nodes -batch -days $validity_days -config $certificate_config_filename -pkeyopt rsa_keygen_bits:2048 -sha256

echo "Generating .p12 file with certificate and private key..."
$openssl_bin pkcs12 -export -in ${account_name}.pem -inkey ${priv_key_name}.nopass.rsakey -out ${account_name}.p12
