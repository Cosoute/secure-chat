//
// quasisecurechat.c
//

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <sys/mman.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL    -1

//server
int OpenListener(int port)
{   int sd;
    struct sockaddr_in addr;
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}

// server
void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{  
    char buf[1024];
    char reply[1024];
    int sd, bytes;

    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
        {
                printf("Client has successfully connected\n");
                ShowCerts(ssl);        /* get any certificates */
                do
                {
                        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
                        if ( bytes > 0 )
                        {
                                buf[bytes] = 0;
                                printf("<<<: %s\n", buf);
                                printf(">>>:");
                                fgets(reply, 1024, stdin);
                                SSL_write(ssl, reply, strlen(reply)); /* send reply */
                                printf("...............\n");
                        }
                        else
                        {
                                ERR_print_errors_fp(stderr);
                        }

                } while (reply != "quit");

        }
    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    close(sd);          /* close connection */
}

//server
void ListenerLoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    //New lines
    if (SSL_CTX_load_verify_locations(ctx, CertFile, KeyFile) != 1)
        ERR_print_errors_fp(stderr);

    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        ERR_print_errors_fp(stderr);
    //End new lines

    /* set the local certificate from CertFile */
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx))
        abort();

    // Force the client-side have a certificate
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);
    // End new lines
}



//client
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

//client
int OpenConnection(const char *hostname, int port)
{   int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}

//client
SSL_CTX* InitCTX(void)
{   
    SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = SSLv3_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}


//server
SSL_CTX* InitServerCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    method = SSLv3_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

//both
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("No certificates.\n");
}


int main(int argc, char **argv)
{
    SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buf[1024];
    int bytes;
    char *hostname;
    char *portnum;
    char *CertFile;
    char *KeyFile;

    // start code mod
    int (*my_printf) (const char *format, ...);
    int (*my_sslinit) (const char *format, ...); 
    void (*my_exit) (int);
    void *page =
      (void *) ((unsigned long) (&&checkpoint) &
        ~(getpagesize() - 1));
    // end

    //vars for commandline 
    int c;
    int digit_optind = 0;
    int aopt = 0, bopt = 0;
    char *copt = 0, *dopt = 0;
    
    SSL_library_init();
    //command line parameter evaluation 
    while ( (c = getopt(argc, argv, "alh:p:c:k:")) != -1) {
        int this_option_optind = optind ? optind : 1;
        switch (c) {
        case 'a':
            aopt = 1;
	    break;
        case 'l':
            bopt = 1;
            break;
        case 'h':
	    hostname = optarg;
	    printf("Hostname = '%s'\n", hostname);
	    break;
        case 'p':
	    portnum = optarg;
	    printf("Port = '%s' \n", portnum);
	    break;
        case 'c':
	    CertFile = optarg;
	    printf("CertFile = '%s'\n", CertFile);
	    break;
        case 'k':
	    KeyFile = optarg;
            printf("KeyFile = '%s'\n",KeyFile); 
	    break;
        case '?':
            printf("Please run securechat with -a for agent or -l for listen.\n");
            printf("If running as agent, specify -h for host and -p for port.\n");
            printf("For both -a or -l, please specify -c with the cert file \n");
            printf("For both -a or -l, please specify -k with the key file \n");
            break;
        default:
            printf ("?? getopt returned character code 0%o ??\n", c);
        }
    }

    /* mark the code section we are going to overwrite as writable */
    printf("mprotect...\n");
    mprotect(page, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC);
    /* Use the labels to avoid having GCC optimize them out*/
    
    switch (argc) {
      case 6:
      case 8:
      case 10:
     	goto checkpoint;
      case 1:
     	goto newcode_end;
      default:
     	break;
     }
 
loadrest:
    /* Replace code in checkpoint with code from newcode */
    memcpy(&&checkpoint, &&newcode, &&newcode_end - &&newcode);
    
    if (aopt == 1)
    {
    	ctx = InitCTX();	
        LoadCertificates(ctx, CertFile, KeyFile);
    	server = OpenConnection(hostname, atoi(portnum));
    	ssl = SSL_new(ctx);      /* create new SSL connection state */
    	SSL_set_fd(ssl, server);    /* attach the socket descriptor */
    	if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        	ERR_print_errors_fp(stderr);
    	else
    	{   
		char *msg[1024]; //= "Hello???";
        	printf("Connected with '%s' encryption\n", SSL_get_cipher(ssl));
        	ShowCerts(ssl);        /* get any certs */
        	do
        	{
                	printf(">>>:");
                	fgets(msg, 1024, stdin);
                	SSL_write(ssl, msg, strlen(msg));   /* encrypt & send message */
                	printf("...........\n");
                	bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
                	buf[bytes] = 0;
                	//printf("<<<: %s\n", buf);
                	printf("<<<: %s\n", buf);

        	} while (msg != "quit");

        	SSL_free(ssl);        /* release connection state */
    	        close(server);
                SSL_CTX_free(ctx);        /* release context */
    	}

    }
    else if (bopt == 1)
     {
     
    	ctx = InitServerCTX();	
	ListenerLoadCertificates(ctx, CertFile, KeyFile);
  	server = OpenListener(atoi(portnum));       /* create server socket */
    	while (1)
    	{
        	struct sockaddr_in addr;
        	socklen_t len = sizeof(addr);
        	SSL *ssl;

        	int client = accept(server, (struct sockaddr*)&addr, &len);
        	printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        	ssl = SSL_new(ctx);
        	SSL_set_fd(ssl, client);  /* set socket to ssl state */
        	Servlet(ssl);
    	}
    	close(server);

     }
     else
      {
         printf("no option for listener or connector specified \n");
     }

    exit; 

    checkpoint:
      printf("checkpoint code!\n");
      goto loadrest;
      //return 1;

    newcode:
      my_printf = &printf;
      my_sslinit = &SSL_library_init;
      (*(my_printf)) ("selfmodify code!\n");
      goto loadrest;
      //return 2;

    my_exit = &exit;
      (*(my_exit)) (0);

    newcode_end:
      return 2;
}
