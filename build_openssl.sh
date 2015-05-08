#!/bin/sh

#openssl优化编译

#查看所有编译选项：
#grep -r '^#if.*OPENSSL_NO' crypto/ ssl/ | grep -o 'OPENSSL_NO_[a-zA-Z0-9_]*' | sort -u | sed 's/OPENSSL_//' | tr '[A-Z_]' '[a-z-]'

#ARCH的选择是看Configure里面的优化选项，选择优化选项相对更合理的，
#32 bit linux-elf比较合适，比较糟糕的如 linux-generic32 就关掉了汇编优化
#64 bit linux-x86_64 比较合适，比较糟糕的如 linux-generic64，也是关掉了汇编优化

#逐选项解释：
#no-shared               \ 不需要.so，只需要.a
#threads                 \ 必须支持thread，初始化的时候，需要调用CRYPTO_set_locking_callback
#no-zlib                 \ 压缩，不需要，有CRIME攻击
#no-bf                   \ blowfish,废弃
#no-buf-freelists        \ 不需要，和HeartBleed攻击有关
#no-camellia             \ camellia，用不到
#no-cast                 \ cast，废弃
#no-comp                 \ comp，压缩，用不到，有CRIME攻击，必须关闭
#no-dtls1                \ dtls，用不到
#no-decc-init            \ 用不到
#no-deprecated           \ 去掉一些废弃的api
#no-dsa                  \ dsa ，用不到
#no-gmp                  \ gmp，用不到
#no-gost                 \ gost，淘汰
#no-heartbeats           \ heartbeats, 用不到，HeartBleed攻击
#no-idea                 \ idea，淘汰
#no-jpake                \ jpake，用不到
#no-krb5                 \ kerberos认证，用不到
#no-libunbound           \ 用libunbound做dns resolve，用不到
#no-md2                  \ md2，淘汰
#no-md4                  \ md4，淘汰
#no-mdc2                 \ mdc2，淘汰
#no-psk                  \ psk，用不到
#no-rc2                  \ rc2，淘汰
#no-rc5                  \ rc5，淘汰
#no-sctp                 \ sctp，用不到
#no-seed                 \ seed，用不到
#no-sha0                 \ sha0，淘汰
#no-srp                  \ srp，用不到
#no-srtp                 \ srtp，用不到
#no-ssl2                 \ ssl2 必须禁用， POODLE攻击
#no-ssl3                 \ ssl3 必须禁用， POODLE攻击
#no-ssl3-method          \ ssl3 必须禁用， POODLE攻击
#no-unit-test            \


function build(){

wget -c https://www.openssl.org/source/$PKG.tar.gz
wget -c https://raw.githubusercontent.com/cloudflare/sslconfig/master/patches/openssl__chacha20_poly1305_cf.patch

#校验一下sha1sum
RIGHT_SHA1=$(curl -k https://www.openssl.org/source/$PKG.tar.gz.sha1)
REAL_SHA1=$(sha1sum openssl-1.0.2a.tar.gz   | cut  -f 1 -d ' ' ) 
if [ "$REAL_SHA1" !=  "$RIGHT_SHA1" ] ;  then
    echo "sha1sum check failed!"
    exit;
fi

rm -rf $PREFIX
mkdir -p $PREFIX

rm -rf $PKG
mkdir -p $PKG
tar xf $PKG.tar.gz
cd $PKG

patch -p1 < ../openssl__chacha20_poly1305_cf.patch

make dclean

./Configure                 \
    --prefix=$PREFIX        \
    $ARCH                   \
    threads                 \
    shared                  \
    no-deprecated           \
    no-dynamic-engine       \
    no-zlib                 \
    no-bf                   \
    no-buf-freelists        \
    no-cast                 \
    no-comp                 \
    no-dtls1                \
    no-decc-init            \
    no-dsa                  \
    no-gmp                  \
    no-gost                 \
    no-heartbeats           \
    no-idea                 \
    no-jpake                \
    no-krb5                 \
    no-libunbound           \
    no-md2                  \
    no-md4                  \
    no-mdc2                 \
    no-psk                  \
    no-rc2                  \
    no-rc4                  \
    no-rc5                  \
    no-sctp                 \
    no-sha0                 \
    no-srp                  \
    no-srtp                 \
    no-ssl2                 \
    no-ssl3                 \
    no-ssl3-method          \
    no-unit-test            

make depend
make
make install -j8

cd ..
rm -rf $PKG 
}




PKG=openssl-1.0.2a

(ARCH="linux-x86_64  enable-ec_nistp_64_gcc_128"
PREFIX=$(pwd)/${PKG}_64_build
build
)

(ARCH=linux-elf
PREFIX=$(pwd)/${PKG}_32_build
#need: sudo yum install libstdc++-devel.i686
export CC="gcc -m32"
#build
)

wait
rm -rf $PKG 
