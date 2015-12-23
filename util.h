#pragma once

#include <string>
#include <vector>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

namespace crypto_tools{

    using std::string;

    enum {
        OK = 0,
        LIB_ERR = -1,
        DATA_ERR = 1,
    };

    class SecureString: public std::string{

        ~SecureString(){
            OPENSSL_cleanse( &(*this)[0],size());
        }
    };


    void init();
}
