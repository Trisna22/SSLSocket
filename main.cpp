#include "SSLSocket.h"


void usage()
{
	printf("SSLSocket [target-ip port] [port]\n\n");
}
int main(int argc, char* argv[])
{
	SSLSocket sslSocket;



	if (argc == 2)
	{
		printf("[*] Create SSL socket for listening!\n");

		int port = 0;
		if ((port = atoi(((string)argv[1]).c_str())) == 0)
		{
			printf("Argument is an invalid port number!\n");
			return 1;
		}

		sslSocket.hostServer(port);
	}
	else if (argc == 3)
	{
		printf("[*] Connecting to ssl server!\n");

		string IP = argv[1];
		int port = 0;
		if ((port = atoi(((string)argv[2]).c_str())) == 0)
		{
			printf("Argument is an invalid port number!\n");
			return 1;
		}

		sslSocket.connectToServer(IP, port);
	}
	else
	{
		usage();
	}
	return 0;
}
