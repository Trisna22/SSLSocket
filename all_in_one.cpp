/*   Private key and certificate   */
#include <openssl/pem.h>
#include <openssl/x509.h>

/*   SSL socket   */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <iostream>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctime>

using namespace std;

void initSSL()
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}
string gen_random(const int len)
{
	string tmp_s;
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	srand( (unsigned) time(NULL) * getpid());

	for (int i = 0; i < len; ++i)
		tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];

	printf("random: %s\n", tmp_s.c_str());
	return tmp_s;
}
bool generateCertificate(EVP_PKEY* public_key, EVP_PKEY* pkey)
{
	X509* x509 = X509_new();
	ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

	X509_set_pubkey(x509, public_key);

	X509_NAME * name;
	name = X509_get_subject_name(x509);

	X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC,
	                   (unsigned char *)"NL", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "ST",  MBSTRING_ASC,
	                   (unsigned char *)"some-state", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
	                   (unsigned char *)gen_random(22).c_str(), -1, -1, 0);

	X509_set_issuer_name(x509, name);
	X509_sign(x509, pkey, EVP_sha1());

	FILE * f = fopen("cert.pem", "wb");
	if (f == NULL)
	{
		printf("Failed to write certificate to file! Error code: %d\n\n", errno);
		return false;
	}

	if (PEM_write_X509(
		f,   /* write the certificate to the file we've opened */
		x509 /* our certificate */
	) == 0)
	{
		printf("Failed to write certificate to file! Error code: %d\n\n", errno);
		return false;
	}

	fclose(f);

	printf("Generated certificate!\n");
	return true;
}
bool generateCertKey()
{
	// Generate private key.
	EVP_PKEY *pkey = EVP_PKEY_new();
	if (!pkey)
	{
		printf("Failed to initalize private key! Error code: %d\n\n", errno);
		return false;
	}

	// Generate the RSA key.
	RSA *rsa = RSA_generate_key(2048, 3, NULL, NULL);
	if (!EVP_PKEY_assign_RSA(pkey, rsa))
	{
		printf("Failed to assign private key to rsa! Error code: %d\n\n", errno);
		return false;
	}

	// Generate public key.
	EVP_PKEY *public_key = EVP_PKEY_new();
	if (!EVP_PKEY_assign_RSA(public_key, rsa))
	{
		printf("Failed to assign public key to rsa! Error code: %d\n\n", errno);
		return false;
	}

	// Generate the BIO for private key.
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, 0, NULL);

	int pem_pkey_size = BIO_pending(bio);
	char *pem_pkey = (char*) calloc((pem_pkey_size)+1, 1);
	BIO_read(bio, pem_pkey, pem_pkey_size);


	FILE *pkey_file = fopen("key.pem", "wb");
	if (!pkey_file)
	{
		std::cerr << "Unable to open \"key.pem\" for writing." << std::endl;
		return false;
	}
	printf("Generated private key!\n");

	bool ret = PEM_write_PrivateKey(pkey_file, pkey, NULL, NULL, 0, NULL, NULL);
	if(!ret)
	{
		std::cerr << "Unable to write private key to disk." << std::endl;
		return false;
	}

	fclose(pkey_file);

	if (!generateCertificate(public_key, pkey))
		return false;

	return true;
}
int create_socket(int port)
{
	int sockfd;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
	{
		printf("Unable to create socket! Error code: %d\n\n", errno);
		return -1;
	}

	if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		printf("Unable to bind the socket! Error code: %d\n\n", errno);
		return -1;
	}

	if (listen(sockfd, 1) < 0)
	{
		printf("Unable to listen for connections! Error code: %d\n\n", errno);
		return -1;
	}

	printf("Succesfully created socket!\n");
	return sockfd;
}
SSL_CTX* create_context()
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = SSLv23_server_method();

	ctx = SSL_CTX_new(method);
	if (!ctx)
	{
		printf("Failed to initialize ctx!\n");
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	return ctx;
}
void configure_context(SSL_CTX *ctx)
{
	SSL_CTX_set_ecdh_auto(ctx, 1);

	/* Set the key and cert */
	if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
		printf("Failed to generate certificate!\n");
		return;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
		ERR_print_errors_fp(stderr);
                printf("Failed to generate key!\n");
		return;
	}

	printf("Certificate and key is imported!\n");
}
int main(int argc, char* argv[])
{
	initSSL();
	if (!generateCertKey())
		return 1;

	SSL_CTX* ctx = create_context();
	if (ctx == NULL)
		return 1;

	configure_context(ctx);

	int sockfd = create_socket(8080);
	if (sockfd == -1)
	{
		printf("Failed to create socket, exiting!\n\n");
		return 1;
	}

	while (true)
	{
		struct sockaddr_in addr;
		uint len = sizeof(addr);
		SSL *ssl;
		const char reply[] = "HTTP/1.1 200 OK\r\n"
			"Server: SSLServer\r\n\r\n<html><h3>"
			"SSLSocket test success!</h3></html>\r\n";

		int client = accept(sockfd, (struct sockaddr*)&addr, &len);
		if (client < 0)
		{
			printf("Failed to accept the connection! Error code: %d\n\n", errno);
			return 1;
		}

		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, client);

		if (SSL_accept(ssl) < 0)
		{
			printf("Failed to SSL_accept a client! Error code: %d\n\n", errno);
			return 1;
		}
		else
		{
			SSL_write(ssl, reply, strlen(reply));
		}

		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(client);
	}

	close(sockfd);
	SSL_CTX_free(ctx);
	EVP_cleanup();
	return 0;
}
