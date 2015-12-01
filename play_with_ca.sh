#!/bin/sh

rm -f riyueshenjiao_root_ca_* dongfangbubai* *.conf

printf "[req]
default_bits            = 4096
default_md              = sha256
prompt                  = no
encrypt_key             = no
string_mask = utf8only
distinguished_name      = ca_distinguished_name
x509_extensions         = ca_cert_ext

[ ca_distinguished_name ]
C  = CN
ST = BJ
L  = BJ
O  = RiYueShenJiao
OU = HeiMuYa
CN = RiYueShenJiao Certification Authority

[ca_cert_ext]
basicConstraints        = critical,CA:true
subjectKeyIdentifier    = hash
authorityKeyIdentifier = keyid:always,issuer:always
keyUsage                = keyCertSign,cRLSign
crlDistributionPoints=URI:http://pki.riyueshenjiao.com/GIAG2.crl
authorityInfoAccess = caIssuers;URI:http://pki.riyueshenjiao.com/GIAG2.crt, OCSP;URI:http://ocsp.riyueshenjiao.com/ocsp
">ca_cert.conf


printf "
[req]
default_bits            = 4096
default_md              = sha256
prompt                  = no
encrypt_key             = no
string_mask             = utf8only
distinguished_name      = dongfangbubai_distinguished_name
req_extensions          = req_x509v3_extensions

[ dongfangbubai_distinguished_name ]
C  = CN
ST = BJ
L  = BJ
O  = dongfangbubai.inc
OU = dongfangbubai.inc R.D.Dept
CN = *.dongfangbubai.com

[req_x509v3_extensions]
basicConstraints = critical,CA:FALSE
subjectKeyIdentifier    = hash
keyUsage = critical,digitalSignature, keyEncipherment
extendedKeyUsage  = critical,serverAuth, clientAuth
crlDistributionPoints=URI:http://pki.riyueshenjiao.com/GIAG2.crl
authorityInfoAccess = caIssuers;URI:http://pki.riyueshenjiao.com/GIAG2.crt, OCSP;URI:http://ocsp.riyueshenjiao.com/ocsp
subjectAltName=@alt_names

[alt_names]
DNS.1 = *.www.dongfangbubai.com
DNS.2 = *.api.dongfangbubai.com
">dongfangbubai_req.conf


printf "
[ ca ]
default_ca = my_ca

[ my_ca ]
serial = ./ca_data/serial
database = ./ca_data/index.txt
new_certs_dir = ./ca_data/
default_md = sha256
default_days = 365
policy = my_policy
x509_extensions = ca_x509v3_extensions
copy_extensions=copy

[ my_policy ]
countryName = supplied
stateOrProvinceName = optional
organizationName = optional
commonName = supplied
organizationalUnitName = optional

[ca_x509v3_extensions]
basicConstraints = critical,CA:FALSE
subjectKeyIdentifier    = hash
authorityKeyIdentifier = keyid:always,issuer:always

">ca_sign.conf


openssl genrsa  -out riyueshenjiao_root_ca_1.key 4096
openssl genrsa  -out riyueshenjiao_root_ca_2.key 4096
openssl ecparam -out riyueshenjiao_root_ca_3.key -name prime256v1 -genkey

for ca in 1 2 3;
do 
    openssl req -new -sha256 -config ca_cert.conf -x509 -days 7300 -key riyueshenjiao_root_ca_$ca.key -out riyueshenjiao_root_ca_$ca.crt
done


openssl genrsa  -out dongfangbubai_1.key 4096
openssl ecparam -out dongfangbubai_2.key -name prime256v1 -genkey


openssl req -new -config dongfangbubai_req.conf  -key dongfangbubai_1.key -out dongfangbubai_1.csr
openssl req -new -config dongfangbubai_req.conf  -key dongfangbubai_2.key -out dongfangbubai_2.csr


mkdir -p ./ca_data/
if [ ! -f ./ca_data/serial ] ; then echo 01 > ./ca_data/serial; fi

for ca in 1 2 3;
do 
    for k in 1 2;
    do
        #openssl x509 -req -sha256 -days 365  -extfile dongfangbubai_req.conf -extensions req_x509v3_extensions -in dongfangbubai_$k.csr -CA riyueshenjiao_root_ca_$ca.crt -CAkey riyueshenjiao_root_ca_$ca.key -CAcreateserial -out dongfangbubai_${k}_by_CA_${ca}.crt
         > ./ca_data/index.txt 
         openssl ca -batch -notext -config ca_sign.conf -in dongfangbubai_$k.csr -cert riyueshenjiao_root_ca_$ca.crt -keyfile riyueshenjiao_root_ca_$ca.key -out dongfangbubai_${k}_by_CA_${ca}.crt
done
done


for ca in 1 2 3;
do 
    for k in 1 2;
    do
        printf "\nCAfile: riyueshenjiao_root_ca_$ca.crt cert: dongfangbubai_${k}_by_CA_${ca}.crt\n"
        openssl x509 -in dongfangbubai_${k}_by_CA_${ca}.crt  -serial -noout
        openssl verify -verbose  -CAfile riyueshenjiao_root_ca_$ca.crt dongfangbubai_${k}_by_CA_${ca}.crt 
    done
done


ca_bundle=/etc/pki/tls/certs/ca-bundle.crt

printf "\n\n\nbefore install root ca certificate\n"
echo "CAfile:" $ca_bundle "cert: " dongfangbubai_*.crt
openssl verify -verbose  -CAfile $ca_bundle dongfangbubai_*.crt 

sudo update-ca-trust enable
sudo cp riyueshenjiao_root_ca_{1,2,3}.crt /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust extract

printf "\n\n\nafter install root ca certificate\n"
echo "CAfile:" $ca_bundle "cert: " dongfangbubai_*.crt
openssl verify -verbose  -CAfile $ca_bundle dongfangbubai_*.crt 

#keytool -printcert -v  -file /etc/pki/tls/certs/ca-bundle.crt

echo '127.0.0.1   www.dongfangbubai.com' | sudo tee -a /etc/hosts
openssl s_server    -cert  dongfangbubai_2_by_CA_3.crt -key dongfangbubai_2.key  -CAfile riyueshenjiao_root_ca_1.key -Verify 3 -accept 4430 -www  &
pid=$$
echo 'GET /HTTP/1.1'|openssl s_client -connect www.dongfangbubai.com:4430 -cert dongfangbubai_1_by_CA_1.crt -key dongfangbubai_1.key -CAfile $ca_bundle
kill $pid
