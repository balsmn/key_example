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
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

std::string convertX509CertificateToString(X509* certificate) {
    std::string certificateString;
    BIO* bio = BIO_new(BIO_s_mem());

    if (bio) {
        if (PEM_write_bio_X509(bio, certificate)) {
            char* buffer;
            long certificateLength = BIO_get_mem_data(bio, &buffer);
            certificateString.assign(buffer, certificateLength);
        }

        BIO_free(bio);
    }

    return certificateString;
}

std::string convertPrivateKeyToString(EVP_PKEY* key) {
    std::string keyString;
    BIO* bio = BIO_new(BIO_s_mem());

    if (bio) {
        if (PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL)) {
            char* buffer;
            long keyLength = BIO_get_mem_data(bio, &buffer);
            keyString.assign(buffer, keyLength);
        }

        BIO_free(bio);
    }

    return keyString;
}
std::string convertPublicKeyToString(EVP_PKEY* key) {
    std::string keyString;
    BIO* bio = BIO_new(BIO_s_mem());

    if (bio) {
        if (PEM_write_bio_PUBKEY(bio, key)) {
            char* buffer;
            long keyLength = BIO_get_mem_data(bio, &buffer);
            keyString.assign(buffer, keyLength);
        }

        BIO_free(bio);
    }

    return keyString;
}

bool extractKeysFromPKCS12(const std::string &pkcs12File, const std::string &password, EVP_PKEY **publicKey, EVP_PKEY **privateKey) {

    int ret = false;
    std::ifstream key_file;
    BIO *bio = BIO_new(BIO_s_mem());
    int bio_write_ret = -1;
    PKCS12 *p12 = NULL;
    std::string p12_file_contents;
    X509 *certificate = NULL;

    key_file.open(pkcs12File, std::iostream::in);

    if (key_file.is_open()) {
        std::cout << "Opened private key (p12 file)." << std::endl;
        //transform key
        std::stringstream key;
        key << key_file.rdbuf();
        p12_file_contents = key.str();
    } else {
        std::cerr << "Couldn't open p12 key file." << std::endl;
        goto cleanup;
    }

    //load private key from file
    bio_write_ret = BIO_write(
            bio, static_cast<const char *>(p12_file_contents.c_str()), p12_file_contents.size());
    if (bio_write_ret <= 0) {
        std::cerr << "error1" << std::endl;
        goto cleanup;
    }

    // Load the PKCS12 file
    p12 = d2i_PKCS12_bio(bio, NULL);

    if (!p12) {
        std::cerr << "Failed to load PKCS12 file." << std::endl;
        goto cleanup;
    } else {
        std::cout << "Loaded PKCS12 file successfully" << std::endl;
    }

    // Parse the PKCS12 file and retrieve the certificate and private key
    if (PKCS12_parse(p12, password.c_str(), privateKey, &certificate, NULL) != 1) {
        std::cerr << "Failed to parse PKCS12 file." << std::endl;
        goto cleanup;
    } else {
        std::cout << "Parsed PKCS12 file successfully" << std::endl;
        std::cout << "X509 Public certificate : " << std::endl << convertX509CertificateToString(certificate) << std::endl;
    }

    // Convert X509 Certificate to EVP_PKEY
    *publicKey = X509_get_pubkey(certificate);
    if (!*publicKey) {
        std::cerr << "Failed to extract public key from X509 certificate." << std::endl;
        goto cleanup;
    }

    ret = true;
cleanup:
    // Clean up
    PKCS12_free(p12);
    X509_free(certificate);
    BIO_free(bio);
    return ret;
}

int main() {
    std::string pkcs12File = "teamsirius_device01.p12";
    std::string password = "IuLZL0eUh1d65eBdburb";
    EVP_PKEY *publicKey = NULL;
    EVP_PKEY *privateKey = NULL;

    if (extractKeysFromPKCS12(pkcs12File, password, &publicKey, &privateKey)) {
        // Public key, Private key extraction successful
        // You can now use them for further operations
        std::cout << "Public EVP_PKEY : " << std::endl << convertPublicKeyToString(publicKey) << std::endl;
        std::cout << "Private EVP_PKEY : " << std::endl << convertPrivateKeyToString(privateKey) << std::endl;
        // Clean up
        EVP_PKEY_free(publicKey);
        EVP_PKEY_free(privateKey);
    } else {
        std::cerr << "Failed to extract public,private keys from PKCS12 file." << std::endl;
        return 1;
    }

    return 0;
}