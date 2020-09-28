#include <iomanip>
#include <string>
#include <string.h>
#include <iostream>
#include <openssl/pem.h>
#include <openssl/x509.h>

int main() {
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        return 0;
    }

    RSA *rsa = RSA_generate_key(2048, 3, NULL, NULL);
    if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
        return 0;
    }

    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, 0, NULL);
    //PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);

    int pem_pkey_size = BIO_pending(bio);
    char *pem_pkey = (char*) calloc((pem_pkey_size)+1, 1);
    BIO_read(bio, pem_pkey, pem_pkey_size);


    FILE *pkey_file = fopen("key.pem", "wb");
    if (!pkey_file) {
        std::cerr << "Unable to open \"key.pem\" for writing." << std::endl;
        return false;
    }

    bool ret = PEM_write_PrivateKey(pkey_file, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(pkey_file);

    if(!ret) {
        std::cerr << "Unable to write private key to disk." << std::endl;
        return false;
    }


    std::cout << pem_pkey << std::endl;

    return 0;
}

