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
$openssl_bin genpkey -algorithm rsa-pss -pkeyopt rsa_keygen_bits:4096 -pkeyopt rsa_keygen_pubexp:65537 -pkeyopt rsa_pss_keygen_mgf1_md:sha256 -pkeyopt rsa_pss_keygen_saltlen:32 -out ${priv_key_name}.rsapsskey
### Save the private key without password protection
$openssl_bin rsa -in ${priv_key_name}.rsapsskey -out ${priv_key_name}.nopass.rsapsskey

echo "Issue certificate signing request (CSR) for the RSASSA-PSS key with parameters in ${certificate_config_filename}"
$openssl_bin req -new -key ${priv_key_name}.nopass.rsapsskey -sha256 -out ${account_name}.csr -config ${certificate_config_filename}
echo "Content of the certificate signing request:"
$openssl_bin req -text -noout -in ${account_name}.csr

echo "Generating self-signed certificate..."
$openssl_bin x509 -req -days ${validity_days} -in ${account_name}.csr -signkey ${priv_key_name}.nopass.rsapsskey -sha256 -out ${account_name}.crt -extensions smime -extfile ${certificate_config_filename}

echo "Generating .p12 file with certificate and private key..."
$openssl_bin pkcs12 -export -in ${account_name}.crt -inkey ${priv_key_name}.nopass.rsapsskey -out ${account_name}.p12
