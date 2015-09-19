#!/bin/sh

openssl genrsa -out svr_test_priv_key.pem 2048
openssl req -new  -batch -out svr_test.csr -key svr_test_priv_key.pem -config openssl.cnf  -utf8
openssl x509 -req -days 3650 -sha256  -in svr_test.csr -signkey svr_test_priv_key.pem -out svr_test_cert.pem -extensions v3_req -extfile openssl.cnf
rm -f svr_test.csr
#openssl x509 -text -in svr_test_cert.pem

openssl ecparam -out svr_test_priv_key_ecdsa.pem -name prime256v1 -genkey
openssl req -new -batch -key svr_test_priv_key_ecdsa.pem -x509 -nodes -sha256 -days 3650 -extensions v3_req -config openssl.cnf -out svr_test_ecdsa_cert.pem  -utf8
#openssl x509 -text -in svr_test_ecdsa_cert.pem

if [ ! -f svr_test_dh.pem ]; then
    echo #openssl dhparam 2048 -out  svr_test_dh.pem 
fi
