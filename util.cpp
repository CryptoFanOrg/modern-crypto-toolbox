#include "util.h"

namespace crypto_tools{

    void EraseMemory(uint8_t * mem, uint32_t mem_len){
        OPENSSL_cleanse(mem,mem_len);
    }


    void init(){
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ERR_load_BIO_strings();
    }

}
