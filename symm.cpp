#include "crypto_toolbox.h"
#include "sys/time.h"

namespace crypto_tools{

    const static int GCM_NONCE_LENGTH=12;
    const static int GCM_TAG_LENGTH=16;


    //key:128
    //encrypt output:nonce(12)+tag(16)+cipher_text
    //no aad
    //
    int Encrypt_AesGcm128(const uint8_t * plain_text, uint32_t plain_text_len,
            const SecureString & key, string & cipher_text){

        cipher_text.clear();
        EVP_CIPHER_CTX ctx;
        EVP_CIPHER_CTX_init(&ctx);

        EVP_CIPHER * cipher=EVP_aes_128_gcm();

        if(1 != EVP_EncryptInit_ex(&ctx, cipher, NULL, NULL, NULL))
            return LIB_ERR;

        unsigned char  nonce[GCM_NONCE_LENGTH]={};
        RAND_bytes(nonce,4);

        struct timeval t={0,0};
        if(0==gettimeofday(&t,NULL)){
            memcpy(&nonce[4],&t.tv_sec,4);
            memcpy(&nonce[8],&t.tv_nsec,4);
        }else{
            RAND_bytes(&nonce[4],GCM_NONCE_LENGTH-4);
        }

        if(1 != EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_LENGTH, NULL))
            return LIB_ERR;

        if(1 != EVP_EncryptInit_ex(&ctx, NULL, NULL, key.data(), &nonce[0]))
            return LIB_ERR;

        cipher_text.reserve(GCM_NONCE_LENGTH+GCM_TAG_LENGTH+plain_text_len);
        cipher_text.append(&nonce[0],GCM_NONCE_LENGTH);
        cipher_text.append(GCM_TAG_LENGTH,0);//fill tag later
        cipher_text.resize(GCM_NONCE_LENGTH+GCM_TAG_LENGTH+plain_text_len);

        //do the real encryption.
        int out_len=plain_text_len;
        const int ret = EVP_CipherUpdate(&ctx,&cipher_text[GCM_NONCE_LENGTH+GCM_TAG_LENGTH],&out_len, plain_text,plain_text_len);
        if(1!=ret){
            cipher_text.clear();
            return LIB_ERR;
        }

        out_len=0;
        if(1 != EVP_CipherFinal_ex(&ctx,cipher_text.end(),out_len) ){
            cipher_text.clear();
            return LIB_ERR;
        }

        /* Get the tag */
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, &cipher_text[GCM_NONCE_LENGTH])){
            cipher_text.clear();
            return LIB_ERR;
        }
        return OK;
    }



    int Decrypt_AesGcm128(const uint8_t * cipher_text, uint32_t cipher_text_len,
            const SecureString & key, string & plain_text){

        EVP_CIPHER_CTX ctx;
        EVP_CIPHER_CTX_init(&ctx);

        EVP_CIPHER * cipher=EVP_aes_128_gcm();

        if(1 != EVP_DecryptInit_ex(&ctx, cipher, NULL, NULL, NULL))
            return false;

        if(1 != EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_LENGTH, NULL))
            return false;

        unsigned char  nonce[GCM_NONCE_LENGTH]={};
        if(1 != EVP_EncryptInit_ex(&ctx, NULL, NULL, key.data(), cipher_text))
            return false;


        int outl=out.size();
        const int ret = EVP_CipherUpdate(&ctx,&out[0],outl,&in[0],in.size());
        if(1==ret){
            out.resize(outl);
            return true;
        }
        out.resize(EVP_CIPHER_CTX_block_size(&ctx));

        /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
        if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
            return false;


        if(1 != EVP_CipherFinal_ex(&ctx,out.data(),outl) ){
            return false;
        }
        out.resize(outl);


        return OK;

    }


    int Encrypt_Chacha20Poly1305(const uint8_t * plain_text, uint32_t plain_text_len,
            const SecureString & key, string & cipher_text);

    int Decrypt_Chacha20Poly1305(const uint8_t * cipher_text, uint32_t cipher_text_len,
            const SecureString & key, string & plain_text);
}
