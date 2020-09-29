#include "stdafx.h"

#ifndef SSL_Socket_H
#define SSL_Socket_H

class SSLSocket
{
private:
	int connectionSocket;
	SSL_CTX* ctx = NULL;
	EVP_PKEY* privateKey = NULL, *publicKey = NULL;
	SSL* ssl;
	string fileNamePrivateKey = "key.pem";
	string fileNameCertificate = "cert.pem";
public:
	SSLSocket();
	bool hostServer(int port, bool createCerts);
	bool connectToServer(string IP, int port);
	void cleanupSSL();
private:
	bool create_server_context();
	bool create_client_context();
	bool configure_context();
	bool generateKeys();
	bool generateCert();
	string random_string(const int len);
};

#endif // !~ SSLSocket_H

SSLSocket::SSLSocket()
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}
bool SSLSocket::hostServer(int port, bool createCertKey = true)
{
	// Create our CTX structure for our socket.
	if (!create_server_context())
		return false;

	// Check if we need to generate some keys and certificate.
	if (createCertKey == true)
	{
		if (!(generateKeys() && generateCert()))
		{
			printf("Failed to generate key or certificate!\n\n");
			return false;
		}

		if (!configure_context())
		{
			printf("Failed to import the generated key and certificate!\n\n");
			return false;
		}
	}
	else
	{
		if (!configure_context())
		{
			printf("Failed to import existing key and certificate!\n\n");
			return false;
		}
	}

	int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sockfd == -1)
	{
		printf("Failed to create a socket! Error code: %d\n\n", errno);
		return false;
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1)
	{
		printf("Failed to bind the socket! Error code: %d\n\n", errno);
		return false;
	}

	if (listen(sockfd, 1) == -1)
	{
		printf("Failed to start listening for connections! Error code: %d\n\n", errno);
		return false;
	}
	printf("[+] Waiting for connections.\n");

	struct sockaddr_in remoteAddr;
	uint len = sizeof(remoteAddr);

	connectionSocket = accept(sockfd, (struct sockaddr*)&remoteAddr, &len);
	if (connectionSocket == -1)
	{
		printf("Failed to accept a connection! Error code: %d\n\n", errno);
		return false;
	}

	printf("\n[+] New client detected, waiting for handshake\n");

	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, connectionSocket);

	if (SSL_accept(ssl) == -1)
	{
		printf("[-] Failed to perform handshake!\n");
		ERR_print_errors_fp(stderr);
		return false;
	}
	else
	{
		printf("[!] Succesfully connected with %s on port %d\n\n",
			inet_ntoa(remoteAddr.sin_addr), remoteAddr.sin_port);
		return true;
	}

}
bool SSLSocket::connectToServer(string IP, int port)
{
	if (!create_client_context())
		return false;

	if (!configure_context())
		return false;

	connectionSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (connectionSocket == -1)
	{
		printf("Failed to create a socket! Error code: %d\n\n", errno);
		return false;
	}

	sockaddr_in remoteAddr;
	remoteAddr.sin_addr.s_addr = inet_addr(IP.c_str());
	remoteAddr.sin_family = AF_INET;
	remoteAddr.sin_port = htons(port);

	if (connect(connectionSocket, (struct sockaddr*)&remoteAddr, sizeof(remoteAddr)) == -1)
	{
		printf("Failed to connect to server! Error code: %d\n\n", errno);
		return false;
	}

	ssl = SSL_new(ctx);
        SSL_set_fd(ssl, connectionSocket);

	printf("\n[+] Connected with server! Performing handshake.\n");

	if (!SSL_connect(ssl))
	{
		printf("[-] Failed to perform handshake with server!\n\n");
		return false;
	}
	else
	{
		printf("[!] Succesfully connected with server!\n\n");
		char msg[] = "Hello from client!";
		SSL_write(ssl, msg, strlen(msg));
		return true;
	}

}
void SSLSocket::cleanupSSL()
{
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	close(connectionSocket);
	EVP_cleanup();
}
bool SSLSocket::create_server_context()
{
	const SSL_METHOD *method;

	method = SSLv23_server_method();
	ctx = SSL_CTX_new(method);
	if (!ctx)
	{
		printf("Failed to initialize ctx!\n");
		ERR_print_errors_fp(stderr);
		return false;
	}

	printf("[+] Context created!\n");
	return true;
}
bool SSLSocket::create_client_context()
{
	const SSL_METHOD *method;

	method = SSLv23_client_method();
	ctx = SSL_CTX_new(method);
	if (!ctx)
        {
                printf("Failed to initialize ctx!\n");
                ERR_print_errors_fp(stderr);
                return false;
        }

	printf("[+] Context created!\n");
	return true;
}
bool SSLSocket::configure_context()
{
	SSL_CTX_set_ecdh_auto(ctx, 1);

	if (SSL_CTX_use_certificate_file(ctx, fileNameCertificate.c_str(), SSL_FILETYPE_PEM) <= 0)
	{
		printf("Failed to import certificate! Error code: %d\n", errno);
		return false;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, fileNamePrivateKey.c_str(), SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		printf("Failed to import key! Error code: %d\n", errno);
		return false;
	}

	printf("[+] Certificate and key has been imported!\n");
	return true;
}
bool SSLSocket::generateKeys()
{
	// Init private key.
	privateKey = EVP_PKEY_new();
	if (!privateKey)
	{
		printf("Failed to init a private key! Error code: %d\n", errno);
		return false;
	}

	// Init public key.
	publicKey = EVP_PKEY_new();
	if (!publicKey)
	{
		printf("Failed to init a public key! Error code: %d\n", errno);
		return false;
	}

	// Generate RSA key.
	RSA *rsa = RSA_generate_key(2048, 3, NULL, NULL);
	if (!(EVP_PKEY_assign_RSA(privateKey, rsa) && EVP_PKEY_assign_RSA(publicKey, rsa)))
	{
		printf("Failed to assign public/private key to the RSA key! Error code: %d\n", errno);
		return false;
	}

	// Generate BIO for private key.
	BIO* bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PrivateKey(bio, privateKey, NULL, NULL, 0, 0, NULL);

	int pem_pkey_size = BIO_pending(bio);
        char *pem_pkey = (char*) calloc((pem_pkey_size)+1, 1);
        BIO_read(bio, pem_pkey, pem_pkey_size);


	// Save private key to file.
	FILE* privateKey_file = fopen(fileNamePrivateKey.c_str(), "wb");
	if (!privateKey_file)
	{
		printf("Failed to create/open the private key file! Error code: %d\n", errno);
		return false;
	}

	if (!PEM_write_PrivateKey(privateKey_file, privateKey, NULL, NULL, 0, NULL, NULL))
	{
		printf("Failed to write the private key to the file! Error code: %d\n", errno);
		return false;
	}

	fclose(privateKey_file);
	printf("[+] Generated private key file!\n");
	return true;
}
bool SSLSocket::generateCert()
{
	if (publicKey == NULL)
	{
		printf("Public key not yet imported or created!\n");
		return false;
	}

	X509* x509 = X509_new();
	ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

	X509_set_pubkey(x509, publicKey);

	X509_NAME * name;
	name = X509_get_subject_name(x509);

	 X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC,
	                   (unsigned char *)"NL", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "ST",  MBSTRING_ASC,
	                   (unsigned char *)"some-state", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
	                   (unsigned char *)random_string(22).c_str(), -1, -1, 0);

	X509_set_issuer_name(x509, name);
	X509_sign(x509, privateKey, EVP_sha1());

	FILE * f = fopen(fileNameCertificate.c_str(), "wb");
	if (f == NULL)
	{
		printf("Failed to write certificate to file! Error code: %d\n\n", errno);
		return false;
	}

	if (PEM_write_X509(f, x509) == 0)
	{
		printf("Failed to write certificate to file! Error code: %d\n\n", errno);
		return false;
	}

	fclose(f);
	printf("[+] Generated certificate file!\n");
	return true;
}
string SSLSocket::random_string(const int len)
{
	string tmp_s;
	static const char alphanum[] =
	"0123456789"
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz";

	srand( (unsigned) time(NULL) * getpid());

	for (int i = 0; i < len; ++i)
		tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];

	return tmp_s;
}
