# ifndef CRYPTO_H
# define CRYPTO_H
# include <openssl/evp.h>
# include <openssl/err.h>
# include <openssl/pem.h>
# include <openssl/core_names.h>
# include <openssl/rand.h>
# include "./config.h"
# include "./common.h"


int import_privatekey(EVP_PKEY ** pkey_pp,const char * privatekey_file){
    
    FILE * fp = fopen(privatekey_file, "r");
    if (fp == NULL) {
        fprintf(stderr, "Unable to open private key file: %s\n", privatekey_file);
        perror("fail reason");
        return 1;
    }

    EVP_PKEY * pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (pkey == NULL) {
        fprintf(stderr, "Error reading private key from file: %s\n", privatekey_file);
        ERR_print_errors_fp(stderr);
        return 1;
    }

    *pkey_pp = pkey;
    return 0;
}


int generate_keypair(const char ** ret_pubkey_pp, const char * privatekey_file){

    char * pubkey;    size_t pubkey_size;

    // generate key pair 
    EVP_PKEY * pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-44");
    
    // extract public key
    EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pubkey_size);
    pubkey = OPENSSL_malloc(PUBLIC_KEY_SIZE);
    EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pubkey, pubkey_size, &pubkey_size);

    // save private key
    FILE *fp = fopen(privatekey_file, "w");
    if (fp==NULL){
        fclose(fp);
        perror("fail reason");
        fprintf(stderr,"%s: open file %s fail: %s\n",__func__, privatekey_file);
        return -1;
    }
    PEM_write_PrivateKey(fp,pkey,NULL,NULL,0,NULL,NULL);

    fclose(fp);
    EVP_PKEY_free(pkey);
    size_t ret_pubkey_size_pp;
    uint8_to_hex(pubkey, pubkey_size, ret_pubkey_pp, &ret_pubkey_size_pp);
    
    return 0;
}


int sign_message(const char * message, const char **signature_pp, EVP_PKEY *pkey)
{   
    size_t message_size= strlen(message);
    
    // set sign configuration
    EVP_PKEY_CTX *sctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    EVP_SIGNATURE *sig_alg = EVP_SIGNATURE_fetch(NULL, "ML-DSA-44", NULL);
    EVP_PKEY_sign_message_init(sctx, sig_alg,NULL);
  
    // sign 
    unsigned char *sig;
    size_t sig_len;
    EVP_PKEY_sign(sctx, NULL, &sig_len, message, message_size);
    sig = OPENSSL_zalloc(sig_len);
    EVP_PKEY_sign(sctx, sig, &sig_len, message, message_size);
    
    size_t signature_size;
    const char * signature;
    uint8_to_hex(sig,sig_len,&signature,&signature_size);

    *signature_pp=append_character(signature,signature_size,'\0');

    // free the ctx and alg
    EVP_SIGNATURE_free(sig_alg);
    EVP_PKEY_CTX_free(sctx);
    return 0;
}

int validate_signature(const char * message, const char * signature, EVP_PKEY * pubkey){

    const unsigned char * _message;
    size_t _message_size;
    hex_to_uint8(message,strlen(message),&_message,&_message_size);

    const unsigned char * _signature;
    size_t _signature_size;
    hex_to_uint8(signature,strlen(signature),&_signature,&_signature_size);

    
    EVP_MD_CTX * ctx = EVP_MD_CTX_new();
    const EVP_MD* md = NULL; // 不使用 digest 算法
    if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, pubkey)>1){
        fprintf(stderr, "EVP_DigestVerify gets problem: ");
        ERR_print_errors_fp(stderr);
    };
    int res= EVP_DigestVerify(ctx, _signature, _signature_size, _message, _message_size);
    if (res<0){
        fprintf(stderr, "EVP_DigestVerify gets problem\n");
        ERR_print_errors_fp(stderr);
    }
    return res;
}


// 随机数生成函数
// 无 '/0' 版本
// const unsigned char * generate_session_id(){
//     size_t session_id_size=SESSION_ID_SIZE;
//     unsigned char * session_id=OPENSSL_zalloc(session_id_size);
//     RAND_bytes(session_id,session_id_size);

//     char * ret_session_id;
//     size_t ret_session_id_size;
//     uint8_to_hex(session_id,session_id_size,&ret_session_id,&ret_session_id_size);
//     return ret_session_id ;
// }

// 有 '/0' 版本
const char * generate_session_id(){
    size_t session_id_size=SESSION_ID_SIZE;
    unsigned char * session_id=OPENSSL_zalloc(session_id_size);
    RAND_bytes(session_id,session_id_size);

    char * hex_session_id;
    size_t hex_session_id_size;
    uint8_to_hex(session_id,session_id_size,&hex_session_id,&hex_session_id_size);
    
    return append_character(hex_session_id,hex_session_id_size,'\0');
}

const char * generate_token(){
    size_t token_size=TOKEN_SIZE;
    unsigned char * token=(unsigned char *)OPENSSL_zalloc(token_size);
    RAND_bytes(token,token_size);

    char * ret_token;
    size_t ret_token_size;
    uint8_to_hex(token,token_size,&ret_token,&ret_token_size);
    return append_character(ret_token,ret_token_size,'\0');
}

const char * generate_email_token(){
    size_t token_size=CHANGE_FACTOR_TOKEN_SIZE;
    unsigned char * token=(unsigned char *)OPENSSL_zalloc(token_size);
    RAND_bytes(token,token_size);

    char * ret_token;
    size_t ret_token_size;
    uint8_to_hex(token,token_size,&ret_token,&ret_token_size);

    return append_character(ret_token,ret_token_size,'\0');
}

const char * generate_challenge(){
    size_t challenge_size=CHALLENGE_SIZE;
    unsigned char * challenge=(unsigned char *)OPENSSL_zalloc(challenge_size);
    RAND_bytes(challenge,challenge_size);
    
    char * ret_challenge;
    size_t ret_challenge_size;
    uint8_to_hex(challenge,challenge_size,&ret_challenge, &ret_challenge_size);

    return append_character(ret_challenge,ret_challenge_size,'\0');
}


# endif