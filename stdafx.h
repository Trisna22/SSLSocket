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
