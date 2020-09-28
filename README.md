# SSLSocket

A example for creating your own ssl sockets.

## Compiling
``` bash
# Compiling the program
g++ -o SSLSocket main.cpp -lssl -lcrypto

# Generate private key and certificate
openssl req -outform PEM -newkey rsa:2048 -nodes -keyout key.pem \
 -x509 -days 365 -out cert.pem
```

# A (little) bit of explainatory
You need to use the code in the pemgenerator.cpp to create your own 
certificate and keys, so you can use the code in server-example.cpp to 
use this for setting up an server.


## Important links
https://wiki.openssl.org/index.php/Category:Examples  
https://wiki.openssl.org/index.php/Simple_TLS_Server  
  

Creating certificate:  
https://stackoverflow.com/questions/256405/programmatically-create-x509-certificate-using-openssl/15082282#15082282  

Demo:  
http://www.opensource.apple.com/source/OpenSSL/OpenSSL-22/openssl/demos/x509/mkcert.c


https://www.commandlinux.com/man-page/man3/SSL.3ssl.html  

