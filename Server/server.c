# include <string.h>
# include <err.h>
# include <sys/socket.h>
# include <sys/select.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
 
static const char cache_id[] = "OpenSSL Demo Server";

int main(int argc, char *argv[])        // 需要两个参数 filename,port
{
    int res = EXIT_FAILURE;
    long opts;
    const char *hostport;

    SSL_CTX *ctx = NULL;
    BIO *acceptor_bio;

    // arguments validation
    if (argc != 2)                                                                         
        errx(res, "Usage: %s [host:]port", argv[0]);
    hostport = argv[1];

    // SSL Ctx setting
    ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        errx(res, "Failed to create server SSL_CTX");
    }

    // SSL version setting
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        errx(res, "Failed to set the minimum TLS protocol version");
    }
 
    // SSL security level setting
    SSL_CTX_set_security_level(ctx, 2);  
    
    // Server Tls connection setting
    opts = SSL_OP_IGNORE_UNEXPECTED_EOF;
    opts |= SSL_OP_NO_RENEGOTIATION; 
    opts |= SSL_OP_CIPHER_SERVER_PREFERENCE;
    SSL_CTX_set_options(ctx, opts);
 
    // Cert and privata key setting
    const char chain_file[]= "../pem/cert/Chain.pem";
    if (SSL_CTX_use_certificate_chain_file(ctx, &chain_file) <= 0) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        errx(res, "Failed to load the server certificate chain file");
    }
    const char key_file[]= "../pem/key/server_key.pem";
    if (SSL_CTX_use_PrivateKey_file(ctx, &key_file, SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        errx(res, "Error loading the server private key file, "
                "possible key/cert mismatch???");
    }

    // Session ctx setting
    SSL_CTX_set_session_id_context(ctx, (void *)cache_id, sizeof(cache_id));
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);

    SSL_CTX_sess_set_cache_size(ctx, 1024);
    SSL_CTX_set_timeout(ctx, 3600); //The default is two hours
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);


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

    /* Wait for incoming connection */
    for (;;) {

        BIO *client_bio;
        SSL *ssl;

        unsigned char buf[8192];
        
        size_t nread;
        size_t nwritten;
        size_t total = 0;

        /* Pristine error stack for each new connection */
        ERR_clear_error();

        /* Wait for the next client to connect （BIO_do_accept）*/ 
        
        if (BIO_do_accept(acceptor_bio) <= 0) {
            /* Client went away before we accepted the connection */
            continue;
        }

        /* Pop the client connection from the BIO chain */
        client_bio = BIO_pop(acceptor_bio);
        fprintf(stderr, "New client connection accepted\n");

        /* Associate a new SSL handle with the new connection */
        if ((ssl = SSL_new(ctx)) == NULL) {
            ERR_print_errors_fp(stderr);
            warnx("Error creating SSL handle for new connection");
            BIO_free(client_bio);
            continue;
        }
        SSL_set_bio(ssl, client_bio, client_bio);

        /* Attempt an SSL handshake with the client */
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            warnx("Error performing SSL handshake with client");
            SSL_free(ssl);
            continue;
        }

        // ZKP Process

        SSL_read_ex(ssl, buf, sizeof(buf), &nread);
        
        fwrite(buf, 1, nread, stdout); 
        // this is client hello message
        // operation: register, login, update information, change password   
        // 
        


        while (SSL_read_ex(ssl, buf, sizeof(buf), &nread) > 0) {         
            
            fwrite(buf, 1, nread, stdout); // 这里的 1 可能要进行调整
            if (SSL_write_ex(ssl, buf, nread, &nwritten) > 0 &&
                nwritten == nread) {
            
                total += nwritten;
                continue;
            }
            warnx("Error echoing client input");
            break;
        }
        fprintf(stderr, "Client connection closed, %zu bytes sent\n", total);
        SSL_free(ssl);
    }

    /*
    * Unreachable placeholder cleanup code, the above loop runs forever.
    */
    SSL_CTX_free(ctx);
    return EXIT_SUCCESS;
 }