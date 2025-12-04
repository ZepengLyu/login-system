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

// #include "server_functions"


static const char cache_id[] = "OpenSSL Demo Server";


int server_process_prim(const char * hostport,const char * chain_file, const char * key_file) 
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
   
    if (SSL_CTX_use_certificate_chain_file(ctx, chain_file) <= 0) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        errx(res, "Failed to load the server certificate chain file");
    }

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


    // Create a listener socket wrapped in a BIO.  
    acceptor_bio = BIO_new_accept(hostport);
    if (acceptor_bio == NULL) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        errx(res, "Error creating acceptor bio");
    }

    // The first call to BIO_do_accept() initialises the socket
    BIO_set_bind_mode(acceptor_bio, BIO_BIND_REUSEADDR);    // 这里是建立并发服务器的关键                                
    if (BIO_do_accept(acceptor_bio) <= 0) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        errx(res, "Error setting up acceptor socket");
    }

 # pragma endregion 
    
 # pragma region functions
    // EVP_PKEY * encap_pkeys=NULL;
    // generate_encapkeys(&encap_pkeys);

    // const *private_key_file="./pem/server_key.pem";

    // BIO * file_bio=BIO_new_file(&private_key_file,"r");

    // EVP_PKEY * private_key=PEM_read_bio_PrivateKey(file_bio,NULL,NULL,NULL);

    // X509 *pubkey_x509 = X509_new();
    // sign2pubkey(private_key,encap_pkeys,pubkey_x509);

    // char * x509_string=NULL;
    // int len=i2d_X509(pubkey_x509,&x509_string);

    // SSL_write(ssl,x509_string,len);

 
    // generate_serverkey();   
    // sign2pubkey();
    // printf("A");

 # pragma endregion
    
 # pragma region 与内部端口连接
    
 # pragma endregion


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
        client_bio = BIO_pop(acceptor_bio);                 // 这里是服务器并行需要修改的地方
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

        // // ZKP Process

        // SSL_read_ex(ssl, buf, sizeof(buf), &nread);
        
        // fwrite(buf, 1, nread, stdout); 
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