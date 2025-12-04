#include <string.h>

#ifdef _WIN32 /* Windows */
# include <winsock2.h>
#else /* Linux/Unix */
# include <sys/socket.h>
#endif

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "../common.h"
// #include "client_functions.h"


/* Helper function to create a BIO connected to the server */
static BIO *create_socket_bio(const char *hostname, const char *port, int family)
{
    int sock = -1;
    BIO_ADDRINFO *res;
    const BIO_ADDRINFO *ai = NULL;
    BIO *bio;

    // Lookup IP address info for the server.
    if (!BIO_lookup_ex(hostname, port, BIO_LOOKUP_CLIENT, family, SOCK_STREAM, 0,
                    &res))
        return NULL;

    // Loop through all the possible addresses for the server and find one we can connect to.
    for (ai = res; ai != NULL; ai = BIO_ADDRINFO_next(ai)) {
        
        // Create the socket according to the family
        sock = BIO_socket(BIO_ADDRINFO_family(ai), SOCK_STREAM, 0, 0);
        if (sock == -1)
            continue;

        // Connect the socket to the server's address
        if (!BIO_connect(sock, BIO_ADDRINFO_address(ai), BIO_SOCK_NODELAY)) {
            BIO_closesocket(sock);
            sock = -1;
            continue;
        }
        // We have a connected socket so break out of the loop
        break;
    }

    // Free the address information resources we allocated earlier
    BIO_ADDRINFO_free(res);

    // If sock is -1 then we've been unable to connect to the server 
    if (sock == -1)
        return NULL;

    // Create a BIO to wrap the socket
    bio = BIO_new(BIO_s_socket());
    if (bio == NULL) {
        BIO_closesocket(sock);
        return NULL;
    }

    // 绑定 bio 和 socket
    BIO_set_fd(bio, sock, BIO_CLOSE); //BIO_CLOSE：标志位，指定BIO对象销毁时自动关闭底层套接字 

    return bio;
}

int client_process_prim(const char * hostname,const char *port,const char *pem_folder) 
{  
    const char *request_start = "GET / HTTP/1.0\r\nConnection: close\r\nHost: ";
    const char *request_end = "\r\n\r\n";

    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO *bio = NULL;
    int res = EXIT_FAILURE;
    int ret;

    size_t written, readbytes;
    char buf[160]; 
    // char *hostname, *port;
    int argnext = 1;
    int ipv6 = 0;

 /* set configuration */

    // Create the TLS_client ctx
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        printf("Failed to create the SSL_CTX\n");
        goto end;
    }

    // Configure the client to abort the handshake if certificate verification fails
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

   
    if (!SSL_CTX_load_verify_dir(ctx,pem_folder)) {
        fprintf(stderr, "Failed to load CA certificates\n");
    }

    // the minimum TLS version is TLSv1.2.
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        printf("Failed to set the minimum TLS protocol version\n");
        goto end;
    }
   
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        printf("Failed to create the SSL object\n");
        goto end;
    }


 /* build socket */
    
    bio = create_socket_bio(hostname, port, ipv6 ? AF_INET6 : AF_INET);
    if (bio == NULL) {
        printf("Failed to create the BIO\n");
        goto end;
    }
    SSL_set_bio(ssl, bio, bio);

    /* Tell the server during the handshake which hostname we are attempting to connect to 
        in case the server supports multiple hosts */
    if (!SSL_set_tlsext_host_name(ssl, hostname)) {
        printf("Failed to set the SNI hostname\n");
        goto end;
    }
    if (!SSL_set1_host(ssl, hostname)) {
        printf("Failed to set the certificate verification hostname");
        goto end;
    } 
    
 /* Do the handshake with the server */
    if (SSL_connect(ssl) < 1) {
        printf("Failed to connect to the server\n");
        if (SSL_get_verify_result(ssl) != X509_V_OK)  // If the failure is due to a verification error we can get more
            printf("Verify error: %s\n",
                X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
        goto end;
    }




 /* Write an HTTP GET request to the peer */
    if (!SSL_write_ex(ssl, request_start, strlen(request_start), &written)) {
        printf("Failed to write start of HTTP request\n");
        goto end;
    }
    if (!SSL_write_ex(ssl, hostname, strlen(hostname), &written)) {
        printf("Failed to write hostname in HTTP request\n");
        goto end;
    }
    if (!SSL_write_ex(ssl, request_end, strlen(request_end), &written)) {
        printf("Failed to write end of HTTP request\n");
        goto end;
    }

    while (SSL_read_ex(ssl, buf, sizeof(buf), &readbytes)) {        
        fwrite(buf, 1, readbytes, stdout);
    }


     /* In case the response didn't finish with a newline we add one now */
    printf("\n");
 
   


    // The 0 argument to SSL_get_error() is the return
    // code we received from the SSL_read_ex() call. It must be 0 in order
    // to get here. Normal completion is indicated by SSL_ERROR_ZERO_RETURN.
    if (SSL_get_error(ssl, 0) != SSL_ERROR_ZERO_RETURN) {
        printf ("Failed reading remaining data\n");
        goto end;
    }
         
     /*
      * The peer already shutdown gracefully (we know this because of the
      * SSL_ERROR_ZERO_RETURN above). We should do the same back.
      */
    ret = SSL_shutdown(ssl);
    if (ret < 1) {
        printf("Error shutting down\n");
        goto end;
    }
 
    /* Success! */
    res = EXIT_SUCCESS;
    end:
        if (res == EXIT_FAILURE)
            ERR_print_errors_fp(stderr);

        // the ownership of bio was immediately transferred to the SSL object
        // via SSL_set_bio(). The BIO will be freed when we free the SSL object.
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return res;
 }