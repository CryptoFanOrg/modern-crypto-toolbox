# modern9
modern9是一个安全，易用，现代，高性能的密码学组件库

1.  密码学是知识背景要求极高，几乎纯数学的一个应用领域，
2.  密码学是通常是高度危险的核心代码，不正确不严密的使用会导致致命的安全危险
3.  这一领域还有大量有恶意的设计后门，人为漏洞
4.  密码学近20年进展巨大，大量算法被破解，大量现代优秀算法得到学界认可,但是大多数程序员眼界有限，无力跟进这些进展
5.  大多数程序员对密码学是无知的，而且并不知道自己不知道什么，完全没有能力鉴别crypto算法的优劣，
6.  另一方面，大多数密码学库的接口又充满的晦涩的crypto术语(例如openssl)

综上，在实际项目中见到太多设计缺陷，不安全，过时，危险的密码学系统后，对比可以发现很多系统只能打70分(及格，但是离业界高水平相距甚远)
所以我希望能设计一个90分的crypto组件库，在安全，易用，现代，高性能方面，能够提升实际项目中密码学的应用水平


modern9分为2部分：
1. 高层filter, box接口，您所遇到的开发问题，90%都已经被这些组件解决
2. 底层密码学算法，如果filter,box不能满足您，请尝试底层原语，底层原语有大量高度危险的细节，请认真阅读注释/文档


### 1.  filter,box
filter,box，亲爱的用户您只需要把它作为一个黑盒来用就行，
如果这个filter/box没有挠到您的痒处，没有让您爽到，那是我的问题，请联系我！


##### 1.
对称传输filter（提供保密+完整性+压缩，保证高性能），

iSymmetricFilter.h

zlib+aes-128-gcm

zlib+aes-128-cbc+hmac-sha256

zlib+chacha20-poly1305

##### 2.
混合加密box，电子信封：

i
rsa-2048 + aes-gcm-128 + hmac-sha256 混合加密，encrypt then MAC
rsa-2048 + aes-cbc-128 + hmac-sha256 混合加密, encrypt then MAC
Curve25519 + chacha20 + poly1305 混合加密，encrypt then MAC

##### 3.
认证密钥协商，提供PFS保证

iKeyExchageFilter.h
ECDSA + ECDH，
rsa-2048
ED25519 + Curve25519

##### 4.
TLS封装

iTLSFilter.h

利用 BIO\_s\_mem 来做tls异步编程： 
<http://funcptr.net/2012/04/08/openssl-as-a-filter-(or-non-blocking-openssl)/>
      

### 2. 底层密码学算法

iSymmetricCipher.h
    aes-gcm-128
    aes-cbc-128
    chacha20-poly1305

iMAC.h
    hmac-sha256
    hmac-sha512

iDigitalSignature.h
    RSA sign/verify
    ECDSA sign/verify
    ED25519 sign/verify

iKeyExchange.h
    RSA encrypt/decrypt
    ECDH
    Curve25519

iPasswordHash.h
    bcrypt
    pbkdf2
    scrypt

iHash.h
    sha256
    sha512
    sha1/md5
    siphash

iCryptoUtil.h
    init()
    mem_cmp_constant_time()
    random


### 4.internal

modern9内部是封装了openssl里面的部分安全，现代，高性能的算法，并没有自己实现

modern9算法的选择参考了 libsodium，Botan，cryptopp, QUIC protocol
<http://doc.libsodium.org/index.html>


