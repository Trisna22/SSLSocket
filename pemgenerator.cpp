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

    // Generate the RSA key
    RSA *rsa = RSA_generate_key(2048, 3, NULL, NULL);
    if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
        return 0;
    }

/*
	TEST
*/
    EVP_PKEY *public_key = EVP_PKEY_new();
    if (!EVP_PKEY_assign_RSA(public_key, rsa))
    {
        printf("Failed to assign public key to rsa!\n\n");
	return 0;
    }

    // Generate the BIO for private key.
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, 0, NULL);

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

    // New code:


    // Generate the BIO for public key.
/*    BIO* bp_public = BIO_new_file("public.pem","w");
    ret = PEM_write_bio_RSAPublicKey(bp_public, rsa);
    if (ret != 1) {
        printf("Failed to write the public key!\n");
        return false;
    }*/



    X509* x509 = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

    X509_set_pubkey(x509, public_key);

    X509_NAME * name;
    name = X509_get_subject_name(x509);

    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC,
                           (unsigned char *)"CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC,
                           (unsigned char *)"MyCompany Inc.", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                           (unsigned char *)"localhost", -1, -1, 0);

    X509_set_issuer_name(x509, name);
    X509_sign(x509, pkey, EVP_sha1());

    FILE * f = fopen("cert.pem", "wb");
    PEM_write_X509(
        f,   /* write the certificate to the file we've opened */
        x509 /* our certificate */
    );

    fclose(f);


    return 0;
}

