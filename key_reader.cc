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

EC_KEY* ecKey = nullptr;
EVP_PKEY* pkey = nullptr;

void setPrivateKeyFromPEM(const std::string& pemkey)
{
    pkey = EVP_PKEY_new();

    BIO* bio = BIO_new(BIO_s_mem());

    int bio_write_ret = BIO_write(
        bio, static_cast<const char*>(pemkey.c_str()), pemkey.size());
    if (bio_write_ret <= 0) {
        throw std::runtime_error("error1");
    }

    if (!PEM_read_bio_PrivateKey(bio, &pkey, NULL, NULL)) {
        throw std::runtime_error("error1.5");
    }

    EC_KEY* eckey_local = EVP_PKEY_get1_EC_KEY(pkey);

    if (!eckey_local) {
        throw std::runtime_error("error2");
    } else {
        ecKey = eckey_local;
        EC_KEY_set_asn1_flag(ecKey, OPENSSL_EC_NAMED_CURVE);
    }
}

std::string getPrivateKeyAsPEM()
{
    if (!pkey) {
        throw std::runtime_error("error3");
    }

    BIO* outbio = BIO_new(BIO_s_mem());

    if (!PEM_write_bio_ECPrivateKey(outbio, ecKey, NULL, NULL, 0, 0,
                                  NULL)) {
        throw std::runtime_error("error4");
    }

    std::string keyStr;
    int         priKeyLen = BIO_pending(outbio);
    keyStr.resize(priKeyLen);
    BIO_read(outbio, (void*)&(keyStr.front()), priKeyLen);
    return keyStr;
}

int main()
{
    std::string expectedPrivKey =
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MIGkAgEBBDBNK0jwKqqf8zkM+Z2l++9r8bzdTS/XCoB4N1J07dPxpByyJyGbhvIy\n"
        "1kLvY2gIvlmgBwYFK4EEACKhZANiAAQvPxAK2RhvH/k5inDa9oMxUZPvvb9fq8G3\n"
        "9dKW1tS+ywhejnKeu/48HXAXgx2g6qMJjEPpcTy/DaYm12r3GTaRzOBQmxSItStk\n"
        "lpQg5vf23Fc9fFrQ9AnQKrb1dgTkoxQ=\n"
        "-----END EC PRIVATE KEY-----\n";

    std::ifstream key_file;

    key_file.open("/tmp/private.key", std::iostream::in);

    if(key_file.is_open()) {
        //transform key
        std::stringstream key;
        key << key_file.rdbuf();
        const std::string& private_key = key.str();

        setPrivateKeyFromPEM(expectedPrivKey);
        // compare priv key
        {
            std::string privKeyRead = getPrivateKeyAsPEM();
            std::cout << privKeyRead << std::endl;
            std::cout<<expectedPrivKey<<std::endl;
        }
    } else {
        std::cout << "Couldn't open private key" << std::endl;
    }

    return 0;
}