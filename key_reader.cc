#include <iostream>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <string>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/decoder.h>
#include <openssl/pem.h>
#include <openssl/param_build.h>
#include <openssl/ec.h>

int main() {
    int ret = 0;
    std::ifstream key_file;
    EVP_PKEY *pkey = EVP_PKEY_new();
    OSSL_LIB_CTX *libctx = NULL;
    EVP_MD_CTX *sign_context = NULL;
    unsigned char *sig_value = NULL;
    const char *sig_name = "SHA-256";
    size_t sig_len = 0;
    const char *payload = "Hello World";

    key_file.open("/data/encrypted/crt/key/key_0.pem", std::iostream::in);

    if(key_file.is_open()) {
        //transform key
        std::stringstream key;
        key << key_file.rdbuf();
        const std::string& private_key = key.str();

        std::cout << "Using private key (" << private_key.size() << " bytes): " << std::endl << private_key << std::endl;

        //load key
        BIO* bio = BIO_new(BIO_s_mem());

        int bio_write_ret = BIO_write(
            bio, static_cast<const char*>(private_key.c_str()), private_key.size());
        if (bio_write_ret <= 0) {
            throw std::runtime_error("error1");
        }

        if (!PEM_read_bio_PrivateKey(bio, &pkey, NULL, NULL)) {
            throw std::runtime_error("error1.5");
        }
        BIO_free(bio);
        //loading private key done

        libctx = OSSL_LIB_CTX_new();
        if (libctx == NULL) {
            fprintf(stderr, "OSSL_LIB_CTX_new() returned NULL\n");
        }

        /*
         * Make a message signature context to hold temporary state
         * during signature creation
         */
        sign_context = EVP_MD_CTX_new();
        if (sign_context == NULL) {
            fprintf(stderr, "EVP_MD_CTX_new failed.\n");
            goto cleanup;
        }
        /*
         * Initialize the sign context to use the fetched
         * sign provider.
         */
        if (!EVP_DigestSignInit_ex(sign_context, NULL, sig_name,
                                  libctx, NULL, pkey, NULL)) {
            fprintf(stderr, "EVP_DigestSignInit_ex failed.\n");
            goto cleanup;
        }
        /*
         * EVP_DigestSignUpdate() can be called several times on the same context
         * to include additional data.
         */
        if (!EVP_DigestSignUpdate(sign_context, payload, strlen(payload))) {
            fprintf(stderr, "EVP_DigestSignUpdate(hamlet_1) failed.\n");
            goto cleanup;
        }
        /* Call EVP_DigestSignFinal to get signature length sig_len */
        if (!EVP_DigestSignFinal(sign_context, NULL, &sig_len)) {
            fprintf(stderr, "EVP_DigestSignFinal failed.\n");
            goto cleanup;
        }
        if (sig_len <= 0) {
            fprintf(stderr, "EVP_DigestSignFinal returned invalid signature length.\n");
            goto cleanup;
        }
        sig_value = (unsigned char*)OPENSSL_malloc(sig_len);
        if (sig_value == NULL) {
            fprintf(stderr, "No memory.\n");
            goto cleanup;
        }
        if (!EVP_DigestSignFinal(sign_context, sig_value, &sig_len)) {
            fprintf(stderr, "EVP_DigestSignFinal failed.\n");
            goto cleanup;
        }

        fprintf(stdout, "Generating signature:\n");
        BIO_dump_indent_fp(stdout, sig_value, sig_len, 2);
        fprintf(stdout, "\n");

        std::cout << "signature: " << sig_value << std::endl;
        std::cout << "signature length: " << sig_len << std::endl;
        return ret;
    } else {
        std::cout << "Couldn't open private key" << std::endl;
        return ret;
    }
cleanup:
        OPENSSL_free(sig_value);
        EVP_MD_CTX_free(sign_context);
        OSSL_LIB_CTX_free(libctx);
        EVP_PKEY_free(pkey);

        return ret;
}