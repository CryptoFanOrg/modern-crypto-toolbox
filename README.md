# modern crypto toolbox
modern crypto toolbox 封装了一系列*易用*，*先进*, *安全*，*高性能*的密码学组件，
modern crypto toolbox 在底层为您选好*最先进*，*最安全*,*最高效*的算法，处理好您不知道的*危险细节*，把算法封装成易于理解的组件，
让您*无痛享用*最先进的密码学技术, 摆脱openssl晦涩费解的api。


modern crypto toolbox提供：
1.  对称加密传输组件，保证:(1)数据加密 (2)数据无法篡改 (你应该知道要加密，可是不一定知道你其实也需要防篡改！[请看][1])
2.  数字信封，就是你所知道的非对称加密
3.  认证密钥协商
4.  密钥拓展函数，用来把一个短密钥变长
5.  用户密码存储/验证函数，scrypt/bcrypt/pbkdf2
6.  TLS封装，网络无关TLS过滤器
7.  密码保险文件存储，用一个密码存储，用一个密码打开
7.  编译，部署，配置方面的best practice脚本


##### 1. 对称加密传输
对称传输filter（提供保密+完整性+压缩），
大多数程序员需要的就是这个对称传输filter

aes-gcm-128
chacha20-poly1305
aes-cbc-128 + hmac-sha256

##### 2.  数字信封，就是你所知道的非对称加密
混合加密box，电子信封，有对方的公钥加密，只有对方才能看到明文(没有PFS保证)
rsa-2048-oaep + aes-gcm-128 混合加密，aead
rsa-2048-oaep + aes-cbc-128 + hmac-sha256 混合加密, encrypt then MAC
ECDH-P256 + aes-gcm-128
ECDH-P256 + chacha20_poly1305 混合加密，aead
Curve25519 + aes-gcm-128
Curve25519 + chacha20_poly1305 混合加密，aead

##### 3.  认证密钥协商
ecdsa + ecdh，
rsa + ecdh，
ed25519 + curve25519

##### 4.  密钥拓展函数
hkdf

##### 5.  用户密码存储/验证函数
scrypt

##### 6.  TLS封装
利用 BIO\_s\_mem 来做tls异步编程： 
<http://funcptr.net/2012/04/08/openssl-as-a-filter-(or-non-blocking-openssl)/>
      

##### 7. 密码保险存储box，用一个密码存储，用一个密码打开，编辑

scrypt + aes-128-gcm



### 2. 底层密码学算法

digital\_signature.h:
    RSA sign/verify
    ECDSA sign/verify
    ED25519 sign/verify

key\_exchange.h:
    RSA encrypt/decrypt
    ECDH P256
    Curve25519

util.h:
    init()
    siphash
    mem_cmp_constant_time()
    random

### 3.deployment build scripts

build\_openssl.sh 这个脚本编译一个安全，高性能的openssl版本

### 4.internal

modern crypto toolbox内部选择封装了openssl里部分安全，现代，高性能的算法，并没有自己实现
modern crypto toolbox参考了 libsodium，Botan，cryptopp, QUIC protocol的设计
modern crypto toolbox依赖openssl，和ed25519-donna, curve25519-donna

1.  大多数程序员对密码学是无知的，而且并不知道自己不知道什么，完全没有能力鉴别crypto算法的优劣
2.  密码学是知识背景要求极高，通常是高度危险的核心代码，不正确不严密的使用会导致致命的安全危险
4.  密码学近20年进展巨大，大量旧算法被破解被淘汰，一些现代优秀算法得到学界认可,但是大多数程序员眼界有限，无力跟进这些进展
5.  openssl等密码学库的接口又充满的晦涩的术语(例如openssl)，对大多数程序员形成误导
6.  很多开源项目中，见到了太多设计缺陷，不安全，过时，危险的设计，这些密码学系统，大多只能打70分，及格，但是离业界高水平相距甚远，尤其是在
中文互联网社区，技术滞后严重
所以，我们需要一个99分的密码学组件库，封装现代密码学的best practic


<http://doc.libsodium.org/index.html>

<http://www.emc.com/emc-plus/rsa-labs/standards-initiatives/what-is-a-digital-envelope.htm>


[1] http://crypto.stackexchange.com/questions/3654/malleability-attacks-against-encryption-without-authentication
