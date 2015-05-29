#pragma once


#include"util.h"

namespace crypto_tools{

    /////////////////////////////对称加密/////////////////////////////
    //保证 confidentiality, integrity, and authenticity 

    int Encrypt_AesGcm128(const uint8_t * plain_text, uint32_t plain_text_len,
            const SecureString & key, string & cipher_text);


    int Decrypt_AesGcm128(const uint8_t * cipher_text, uint32_t cipher_text_len,
            const SecureString & key, string & plain_text);


    int Encrypt_Chacha20Poly1305(const uint8_t * plain_text, uint32_t plain_text_len,
            const SecureString & key, string & cipher_text);

    int Decrypt_Chacha20Poly1305(const uint8_t * cipher_text, uint32_t cipher_text_len,
            const SecureString & key, string & plain_text);




    /////////////////////////////数字信封/////////////////////////////
    //rsa-2048-oaep + aes-gcm-128 混合加密，aead
    //curve25519 + chacha20 + poly1305 混合加密，aead

    int Encrypt_RsaAesGcm128(EVP_PKEY * public_key, const uint8_t * plain_text, uint32_t plain_text_len, string & cipher_text);
    int Decrypt_RsaAesGcm128(EVP_PKEY * public_key, const uint8_t * plain_text, uint32_t plain_text_len, string & cipher_text);

    int Encrypt_Curve25519Chacha20Poly1305(EVP_PKEY * public_key, const uint8_t * plain_text, uint32_t plain_text_len, string & cipher_text);
    int Decrypt_Curve25519Chacha20Poly1305(EVP_PKEY * public_key, const uint8_t * plain_text, uint32_t plain_text_len, string & cipher_text);




    /////////////////////////////认证密钥交换/////////////////////////////
    //单向认证(client 认证服务器的身份)
    // rsa + ecdh,
    // ecdsa + ecdh，
    // ed25519 + curve25519


    struct SignVerifyCtx{
        string certificate;
        SecureString certificate_private_key;
    };

    struct KeyExchangeCtx{
        SecureString private_key_for_exchange;
        string public_key_for_exchange;
    };

    struct KeyExchangeMsg{
        string random;
        string public_key_for_exchange;
        string public_key_signature;
    };


    struct ServerCtx{
        KeyExchangeCtx exchange_ctx;
        SignVerifyCtx  cert_ctx;
        string server_random;

        SecureString shared_key;

        uint32_t use_count;
        const static uint32_t MAX_REUSE_COUNT=1000;//以上CTX最多重复使用次数，但是为了保证PFS特性，只能重复使用一定次数
    };

    struct ClientCtx{
        KeyExchangeCtx exchange_ctx;
        SignVerifyCtx  cert_ctx;
        string client_random;

        SecureString shared_key;
    };

    //1.GenerateKeyPair
    int GenerateKeyPairForExchange_Curve25519( KeyExchangeCtx & ctx );

    //2.Sign local KeyExchangeCtx.public_key_for_exchange
    int SignPublicKey(const SecureString & local_certificate_private_key, const string & public_key_for_exchange, string & public_key_signature);
    //3.build a KeyExchangeMsg , send it to peer
    //4.verify received KeyExchangeMsg, using SignVerifyCtx.certificate (peer_certificate)
    int VerifyPublicKey(const string & peer_certificate, const string & public_key_for_exchange, const string & public_key_signature);

    //5.generate shared_key
    int ExchangeSharedKey_Curve25519(const string & peer_public_key_for_exchange, const string & local_private_key_for_exchange, SecureString & shared_key);




    /////////////////////////////用户密码hash存储/验证/////////////////////////////
    //scrypt,带sse2优化
    int HashPassword_Scrypt(const uint8_t * password, uint32_t password_len, string & store_hash);
    int VerifyPassword_Scrypt(const uint8_t * password, uint32_t password_len, const uint8_t * store_hash, uint32_t store_hash_len);




    /////////////////////////////TLS Transform/////////////////////////////
    class TLSTransform{
        public:
            int putAppData(const uint8_t * buff, uint32_t buff_len);
            int putTLSData(const uint8_t * buff, uint32_t buff_len);

            int getTLSDataToSend(string & buff);
            int getAppDataToConsume(string & buff);

        private:
            BIO * bio_on_string;


            string tls_data;
            string app_data;

    };



    /////////////////////////////密钥延长/////////////////////////////
    //把一个短密钥延长成一个长密钥
    //注意，这个函数是用来做密钥延长的，不能用来处理password，处理password请用上面的 PasswordScrypt 函数
    int KDF_HKDF_SHA256(const uint8_t * shared_key, uint32_t shared_key_len, 
            const uint8_t * salt, uint32_t salt_len, 
            uint32_t start_at_pos, uint32_t end_at_pos,
            string & derived_key);



    void EraseMemory(uint8_t * mem, uint32_t mem_len);



}
