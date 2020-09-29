# SSLSocket

A example for creating your own ssl sockets.

## Compiling
``` bash
# Compiling the program
g++ -o SSLSocket main.cpp -lssl -lcrypto

# Generate private key and certificate
openssl req -outform PEM -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem
```

## A (little) bit of explainatory
You need to use the code in the pemgenerator.cpp to create your own 
certificate and keys, so you can use the code in server-example.cpp to 
use this for setting up an server.


### Creating a ssl socket server
``` c++
create_context();	// Creating ctx structure.
generateKeys();		// Generating private key (optional)
generateCert();		// Generate certificate (optional)

configure_context();	// Importing key and cert file.

createSockets(port);	// Simple create tcp socket.

// Accept a client.
connectionSocket = accept(sockfd, (struct sockaddr*)&remoteAddr, &len);

// Set the SSL object for our encrypted messaging.
ssl = SSL_new(ctx);
SSL_set_fd(ssl, connectionSocket); // Specify socket.

SSL_accept(ssl) // Perform handshake with client.

// The rest is up to you.
SSL_write(ssl, buffer, strlen(buffer)); // Writing to socket.
SSL_read(ssl, buffer, strlen(buffer)); // Reading from socket.

```

### Creating a ssl socket client
``` c++
create_context();       // Creating ctx structure.
generateKeys();         // Generating private key (optional)
generateCert();         // Generate certificate (optional)

configure_context();    // Importing key and cert file.

createSockets(port);    // Simple create tcp socket.

// Connect to server.
connect(connectionSocket, (struct sockaddr*)&remoteAddr, sizeof(remoteAddr));

// Set the SSL object for our encrypted messaging.
ssl = SSL_new(ctx);
SSL_set_fd(ssl, connectionSocket); // Specify socket.


SSL_connect(ssl); // Perform handshake on server.

// The rest is up to you.
SSL_write(ssl, buffer, strlen(buffer)); // Writing to socket.
SSL_read(ssl, buffer, strlen(buffer)); // Reading from socket.

```

### Cleanup
``` c++
SSL_shutdown(ssl);	// shutdowns socket.
SSL_free(ssl);		// free SSL object.
SSL_CTX_free(ctx);	// free CTX object.
close(connectionSocket);// close socket.
EVP_cleanup();		// Cleanup openssl libary.

``` 
## Important links
https://wiki.openssl.org/index.php/Category:Examples  
https://wiki.openssl.org/index.php/Simple_TLS_Server  
  

Creating certificate:  
https://stackoverflow.com/questions/256405/programmatically-create-x509-certificate-using-openssl/15082282#15082282  

Demo:  
http://www.opensource.apple.com/source/OpenSSL/OpenSSL-22/openssl/demos/x509/mkcert.c


https://www.commandlinux.com/man-page/man3/SSL.3ssl.html  

