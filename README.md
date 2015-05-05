# modern99
modern99是一个开箱即用，安全，易用，现代，高性能的密码学组件封装库

鉴于：

1.  大多数程序员对密码学是无知的，而且并不知道自己不知道什么，完全没有能力鉴别crypto算法的优劣
2.  密码学是知识背景要求极高，通常是高度危险的核心代码，不正确不严密的使用会导致致命的安全危险
4.  密码学近20年进展巨大，大量旧算法被破解被淘汰，一些现代优秀算法得到学界认可,但是大多数程序员眼界有限，无力跟进这些进展
5.  openssl等密码学库的接口又充满的晦涩的术语(例如openssl)，对大多数程序员形成误导

在很多开源项目中，见到了太多设计缺陷，不安全，过时，危险的设计，这些密码学系统，大多只能打70分，及格，但是离业界高水平相距甚远，尤其是在
中文互联网社区，技术滞后严重
所以，我们需要一个99分的密码学组件库，封装现代密码学的best practic


modern99分为2部分：

1.  高层filter, box组件，您所遇到的开发问题，90%都已经被这些组件解决，并且内置best practice，请直接使用
2.  底层密码学算法，如果filter,box不能满足您，请尝试底层原语，底层原语有大量高度危险的细节，请认真阅读注释/文档
3.  编译，部署，配置方面的best practice脚本


### 1.  filter,box

##### 1.  对称传输filter（提供保密+完整性+压缩），
大多数程序员需要的就是这个对称传输filter

symmetric\_filter.h

zlib+aes-128-gcm

zlib+aes-128-cbc+hmac-sha256

zlib+chacha20-poly1305

##### 2.  认证密钥协商，提供PFS保证

keyexchage\_filter.h

ECDSA + ECDH

rsa-2048

ED25519 + Curve25519

PRF，密码拓展函数

##### 3.  混合加密box，电子信封，有对方的公钥加密，只有对方才能看到明文(没有PFS保证)

digital\_envelope.h

rsa-2048 + aes-gcm-128 + hmac-sha256 混合加密，encrypt then MAC

rsa-2048 + aes-cbc-128 + hmac-sha256 混合加密, encrypt then MAC

ECDH-P256 + chacha20 + poly1305 混合加密，encrypt then MAC

Curve25519 + chacha20 + poly1305 混合加密，encrypt then MAC


##### 4.  TLS封装，提供TLS best practice

tls\_filter.h

利用 BIO\_s\_mem 来做tls异步编程： 
<http://funcptr.net/2012/04/08/openssl-as-a-filter-(or-non-blocking-openssl)/>
      
##### 5. 密码保险存储box，用一个密码存储，用一个密码打开，编辑

store\_box.h

scrypt + aes-128-gcm

### 2. 底层密码学算法

digital\_signature.h:
    RSA sign/verify
    ECDSA sign/verify
    ED25519 sign/verify

key\_exchange.h:
    RSA encrypt/decrypt
    ECDH
    Curve25519

password\_hash.h:
    bcrypt
    pbkdf2
    scrypt
    PRF_sha256

hash.h:
    sha256
    sha512
    sha1/md5
    siphash

crypto\_util.h:
    init()
    mem_cmp_constant_time()
    random

### 3.deployment build scripts

build_openssl.sh 这个脚本编译一个安全，高性能的openssl版本

### 4.internal

modern99内部选择封装了openssl里部分安全，现代，高性能的算法，并没有自己实现

modern99算法的选择参考了 libsodium，Botan，cryptopp, QUIC protocol
<http://doc.libsodium.org/index.html>

<http://www.emc.com/emc-plus/rsa-labs/standards-initiatives/what-is-a-digital-envelope.htm>
