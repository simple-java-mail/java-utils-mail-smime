#!/bin/bash

# This script can be used to generate a self-signed test-certificate for the fictional principal "Bob".
# The certificate is issued on the basis of a RSASSA-PSS key-pair.

### Set the openssl version to use. Must be OpenSSL 1.1 for RSASSA-PSS support
openssl_bin="/usr/local/opt/openssl@1.1/bin/openssl"
account_name="bob"
priv_key_name="${account_name}.priv"
certificate_config_filename="${account_name}.cnf"
validity_days=1825 # Five years, so the tests won't fail too soon.

echo "Generating private RSASSA-PSS key"
$openssl_bin genpkey -algorithm rsa-pss -pkeyopt rsa_keygen_bits:4096 -pkeyopt rsa_keygen_pubexp:65537 -pkeyopt rsa_pss_keygen_md:sha256 -pkeyopt rsa_pss_keygen_mgf1_md:sha256 -pkeyopt rsa_pss_keygen_saltlen:32 -out ${priv_key_name}.rsapsskey
### Save the private key without password protection
$openssl_bin rsa -in ${priv_key_name}.rsapsskey -out ${priv_key_name}.nopass.rsapsskey

echo "Generating self-signed certificate..."
$openssl_bin req -outform PEM -out ${account_name}.pem -key ${priv_key_name}.nopass.rsapsskey -keyform PEM -x509 -nodes -batch -days $validity_days -config $certificate_config_filename -pkeyopt rsa_keygen_bits:4096 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sigopt rsa_mgf1_md:sha256 -sha256

echo "Generating .p12 file with certificate and private key..."
$openssl_bin pkcs12 -export -in ${account_name}.pem -inkey ${priv_key_name}.nopass.rsapsskey -out ${account_name}.p12
