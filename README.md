# reysecure-chat
secure chat client/server using self modifying run-time code making difficult to reverse engineer the binary


## README TO REYSECURE-CHAT

Article https://www.reysec.com/post/type-1-hyper-visor-with-true-crypt

The reysecure-chat program that uses encrypted communications and self-modifying run time code that rewrites code in memoryto throw off run time inspection or reverse engineering efforts.  It was written in C and built and run on linux kernel 3.13 (ubuntu 14.04.1)

1.) The source code consists of a single file: quasi-secure.chat.c

2.) Source code snippets were taken from the following:
a.) OpenSSL connection sample: http://simplestcodings.blogspot.com.br/2010/08/secure-server-client-using-openssl-in-c.html

b.) Self-Modifying code sample: http://nmav.gnutls.org/2011/12/self-modifying-code-using-gcc.html 


3.) To build, type in "./build" within the directory 

4.) before building, please install opensslv3

5.) Once it has been built, a binary file "quasi-secure-chat" should be generated.  

6.) Install the CA crt, as follows
6a. Copy your certificate to the system certificate directory. At a terminal prompt, type:
$ sudo cp ca.crt /usr/share/ca-certificates/ca.crt
6b. Edit the ca-certificates configuration file /etc/ca-certificates.conf. Add the name of the file you copied to /usr/share/ca-certificates to the top of the list just after the final "#". 

7.) To run as listener:
#> ./listener.sh
(e.g. password = "test123")

8.) To run as connector:
#> ./connector.sh
(e.g. password = "client123")

9.) reysecure-chat uses OpenSSLv3 to encrypt data transfer between listener and connector.  The listener has the server side keys.  The connector has the client side keys.  Both sides require to exchange their public keys to be validated and decrypt by the other party.

10.) The cert and private keys are needed for both connector and listener.  The cert and key files can be specified as a command line parameter and have been included in the bash scripts for listener.sh and connector.sh.

11.) reysecure-chat uses mprotect (to change memory write permissions) and memcpy(to change pointer functions) and labels (to jump to sections) in ordrer to rewrite code in memory.  The code that is rewritten in memory simply adds in a call to SSL (SSL_init) that will cause the program to fail execution if it is not written - thus preventing tampering.

12.) The code is not pretty.  I didn't have much time to clean up and/or refactor. It's all very basic C code.


Let me know if you have any questions:  reynjames67@gmail.com

-- James    

