#!/bin/sh

rm -f riyueshenjiao_root_ca_* dongfangbubai* *.conf

printf "[req]
default_bits            = 4096
default_md              = sha256
prompt                  = no
encrypt_key             = no
string_mask = utf8only
distinguished_name      = ca_distinguished_name

[ ca_distinguished_name ]
C  = CN
ST = BJ
L  = BJ
O  = RiYueShenJiao
OU = HeiMuYa
CN = RiYueShenJiao Certification Authority

[x509v3_extensions]
basicConstraints        = CA:true
subjectKeyIdentifier    = hash
keyUsage                = keyCertSign,cRLSign
crlDistributionPoints=URI:http://pki.riyueshenjiao.com/GIAG2.crl
authorityInfoAccess = caIssuers;URI:http://pki.riyueshenjiao.com/GIAG2.crt, OCSP;URI:http://ocsp.riyueshenjiao.com/ocsp
">ca_v3.ext.conf


printf "
[req]
default_bits            = 4096
default_md              = sha256
prompt                  = no
encrypt_key             = no
string_mask = utf8only
distinguished_name      = dongfangbubai_distinguished_name

[ dongfangbubai_distinguished_name ]
C  = CN
ST = BJ
L  = BJ
O  = dongfangbubai.inc
OU = dongfangbubai.inc R.D.Dept
CN = dongfangbubai.com

[req_x509v3_extensions]
subjectKeyIdentifier    = hash
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage  = serverAuth, clientAuth
authorityKeyIdentifier=keyid,issuer
crlDistributionPoints=URI:http://pki.riyueshenjiao.com/GIAG2.crl
authorityInfoAccess = caIssuers;URI:http://pki.riyueshenjiao.com/GIAG2.crt, OCSP;URI:http://ocsp.riyueshenjiao.com/ocsp
subjectAltName=@alt_names

[alt_names]
DNS.1 = *.nichunyuan.com
">req_v3.ext.conf


openssl genrsa  -out riyueshenjiao_root_ca_1.key 4096
openssl genrsa  -out riyueshenjiao_root_ca_2.key 4096
openssl ecparam -out riyueshenjiao_root_ca_3.key -name prime256v1 -genkey

for ca in 1 2 3;
do 
    openssl req -new -sha256 -config ca_v3.ext.conf -extensions x509v3_extensions -x509 -days 7300 -key riyueshenjiao_root_ca_$ca.key -out riyueshenjiao_root_ca_$ca.crt
done

openssl genrsa  -out dongfangbubai_1.key 4096
openssl ecparam -out dongfangbubai_2.key -name prime256v1 -genkey
openssl req -new -config req_v3.ext.conf  -key dongfangbubai_1.key -out dongfangbubai_1.csr
openssl req -new -config req_v3.ext.conf  -key dongfangbubai_2.key -out dongfangbubai_2.csr

for ca in 1 2 3;
do 
    for k in 1 2;
    do
        openssl x509 -req -sha256 -days 365  -extfile req_v3.ext.conf -extensions req_x509v3_extensions -in dongfangbubai_$k.csr -CA riyueshenjiao_root_ca_$ca.crt -CAkey riyueshenjiao_root_ca_$ca.key -CAcreateserial -out dongfangbubai_${k}_by_CA_${ca}.crt
done
done


for ca in 1 2 3;
do 
    for k in 1 2;
    do
        printf "\nCAfile: riyueshenjiao_root_ca_$ca.crt cert: dongfangbubai_${k}_by_CA_${ca}.crt\n"
        openssl verify -verbose  -CAfile riyueshenjiao_root_ca_$ca.crt dongfangbubai_${k}_by_CA_${ca}.crt 
    done
done


ca_bundle=/etc/pki/tls/certs/ca-bundle.crt
echo "CAfile:" $ca_bundle "cert: " dongfangbubai_*.crt
openssl verify -verbose  -CAfile $ca_bundle dongfangbubai_*.crt 

sudo update-ca-trust enable
sudo cp riyueshenjiao_root_ca_*.crt /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust extract

echo "CAfile:" $ca_bundle "cert: " dongfangbubai_*.crt
openssl verify -verbose  -CAfile $ca_bundle dongfangbubai_*.crt 

keytool -printcert -v  -file /etc/pki/tls/certs/ca-bundle.crt
