# include <string.h>
#ifdef _WIN32 /* Windows */
# include <stdarg.h>
# include <winsock2.h>
#else /* Linux/Unix */
# include <err.h>
# include <sys/socket.h>
# include <sys/select.h>
#endif
# include <openssl/bio.h>
# include <openssl/ssl.h>
# include <openssl/err.h>
# include <openssl/pem.h>


# include "./server_api.h"

static const char cache_id[] = "OpenSSL Demo Server";


int server_process(const char * hostport,const char * chain_file,const char * key_file) 
{
    int res = EXIT_FAILURE;
    
 /* set configuration */ 
    
    SSL_CTX *ctx = NULL;
    BIO *acceptor_bio;

    // Set SSL ctx
    ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        errx(res, "Failed to create server SSL_CTX");
    }

    // Set SSL version 
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        errx(res, "Failed to set the minimum TLS protocol version");
    }

    // Set SSL security level 
    SSL_CTX_set_security_level(ctx, 2);  
    
    // Set Server TlS connection 
    long opts;
    opts = SSL_OP_IGNORE_UNEXPECTED_EOF;
    opts |= SSL_OP_NO_RENEGOTIATION; 
    opts |= SSL_OP_CIPHER_SERVER_PREFERENCE;
    SSL_CTX_set_options(ctx, opts);
 

    // Set cert and private key
    // char chain_file[]= "./pem/chain.pem";
    if (SSL_CTX_use_certificate_chain_file(ctx, chain_file) <= 0) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        errx(res, "Failed to load the server certificate chain file");
    }

    // char key_file[]= "./pem/server_key.pem";

    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        errx(res, "Error loading the server private key file, "
                "possible key/cert mismatch???");
    }

    // Set Session ctx 
    SSL_CTX_set_session_id_context(ctx, (void *)cache_id, sizeof(cache_id));
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);

    SSL_CTX_sess_set_cache_size(ctx, 1024);
    SSL_CTX_set_timeout(ctx, 3600); //The default is two hours
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    MYSQL * my_connection=connect_database();

 /* build socket*/ 
    // Create a listener socket wrapped in a BIO.  
    acceptor_bio = BIO_new_accept(hostport);
    if (acceptor_bio == NULL) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        errx(res, "Error creating acceptor bio");
    }

    // The first call to BIO_do_accept() initialises the socket
    BIO_set_bind_mode(acceptor_bio, BIO_BIND_REUSEADDR);          

    if (BIO_do_accept(acceptor_bio) <= 0) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        errx(res, "Error setting up acceptor socket");
    }

 # pragma endregion 
    
    /* Wait for incoming connection */
    for (;;) {

        BIO *client_bio;
        SSL *ssl;
    
        // Pristine error stack for each new connection
        ERR_clear_error(); 

        //  Wait for the next client to connect （BIO_do_accept）
        if (BIO_do_accept(acceptor_bio) <= 0) {
            /* Client went away before we accepted the connection */
            continue;
        }

        // Pop the client connection from the BIO chain 
        client_bio = BIO_pop(acceptor_bio);                 
        fprintf(stderr, "New client connection accepted\n");

        // Associate a new SSL handle with the new connection
        if ((ssl = SSL_new(ctx)) == NULL) {
            ERR_print_errors_fp(stderr);
            warnx("Error creating SSL handle for new connection");
            BIO_free(client_bio);
            continue;
        }
        SSL_set_bio(ssl, client_bio, client_bio);

        // Attempt an SSL handshake with the client 
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            warnx("Error performing SSL handshake with client");
            SSL_free(ssl);
            continue;
        }
        
        server_listen(ssl,my_connection);
    
        SSL_free(ssl);
    }

    SSL_CTX_free(ctx);
    return EXIT_SUCCESS;
 }