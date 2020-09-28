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

## Important links
https://wiki.openssl.org/index.php/Simple_TLS_Server  
https://www.commandlinux.com/man-page/man3/SSL.3ssl.html  

