#ifndef COMMON_H
#define COMMON_H
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include "./config.h"
#include "./message_type.h"
#include <openssl/ssl.h>
#include <stdio.h>  
#include <fcntl.h>
#include <errno.h>


const char * append_character(const char * token,size_t token_size, char c){
    char * token_text= (char *)malloc(token_size + 1);
    memcpy(token_text,token,token_size);
    free(token);
    token_text[token_size]=c;
    return token_text;
}

size_t find_delimiter(const char * buf, size_t buf_size, size_t index){
    //这里 index 是 the start point to find
    char* result = (char*)memchr(buf+index,0x0A,buf_size-index);
    return result-buf;
}


const char * fill_with_va(char message_type, int data_count,...){

    // 首先获得 text 的长度
    va_list args;
    size_t text_len=1; // message_type

    va_start(args, data_count);
    for (int i = 0; i < data_count; i++) {
        const  char * data = va_arg(args, const char *);
        text_len += 1+strlen(data);

    }
    va_end(args);

    char *text = OPENSSL_zalloc(text_len);
    if (text==NULL){
        fprintf(stderr,"text allocation gets problem");
        exit(1);
    }

    // 填入数据
    text[0]=message_type;
    int offset=1;
    va_start(args, data_count);
    for (int i = 0; i < data_count; i++) {
        const char * data  = va_arg(args, const char *);
        size_t data_size = strlen(data);
        
        text[offset]='\n';
        offset++;
        if (data && data_size > 0) {
            memcpy(text + offset, data, data_size);
            offset += data_size;
        }

    }
    va_end(args);
    const char *ret_message=append_character(text,text_len,'\0');
    return ret_message;
}

int get_with_va(const char * text, size_t text_size, int data_count,...){
   
    if (data_count <= 0) {
        fprintf(stderr,"data count<=0");
        return 1;
    }

    // 确定 delimiter '\n' 的位置
    size_t delimiter_indices[data_count];
    size_t offset=0;
    for (int i=0;i<data_count;i++){
        delimiter_indices[i]=find_delimiter(text, text_size, offset); 
        offset= delimiter_indices[i]+1;
    }

    va_list args;
    va_start(args,data_count);
    
    for (int i=0;i<data_count-1;i++){
        const char ** data_pp=va_arg(args, const char **);
        size_t _data_size=delimiter_indices[i+1]-delimiter_indices[i]-1;
        char *_data = OPENSSL_zalloc(_data_size+1);  
        memcpy(_data, text+delimiter_indices[i]+1, _data_size);
        _data[_data_size]='\0';
        *data_pp=_data;
    }

    const char ** data_pp=va_arg(args, const char **);

    size_t _data_size=text_size-delimiter_indices[data_count-1]-1;
    char *_data = OPENSSL_zalloc(_data_size);  
    memcpy(_data, text+delimiter_indices[data_count-1]+1, _data_size);
    
    *data_pp=_data;
   
    return 0;
}
int uint8_to_hex(const unsigned char * text, size_t text_size, const char ** hex_text_pp, size_t * hex_text_p){
    
    size_t _hex_text_size=text_size*2;
    char * _hex_text=malloc(_hex_text_size+1); // 由于 snprintf 的特性，未结尾留出一个 '\0'
    memset(_hex_text,48,_hex_text_size); // 48 refers to '0' in ascaii
    
    size_t offset=0;
    for (int i=0;i<text_size;i++){  
        sprintf(_hex_text+offset,"%02X", text[i]);
        offset+=2;
    }
    * hex_text_pp=_hex_text;
    * hex_text_p=_hex_text_size;
    return 0;
}

int hex_to_uint8(const char * text, size_t text_size, const unsigned char ** uint8_text_pp, size_t * uint8_text_p){
    size_t _uint8_text_size=text_size/2;
    char * _uint8_text=malloc(_uint8_text_size);
    memset(_uint8_text,0,_uint8_text_size); 
    
    size_t offset=0;
    for (int i=0;i<_uint8_text_size;i++){  
        sscanf(text+offset, "%2hhx", _uint8_text+i);
        offset+=2;
    }

    * uint8_text_pp=_uint8_text;
    * uint8_text_p=_uint8_text_size;
    return 0;
}


char * get_datetime_str(){ 
    size_t timestamp = time(NULL);
    struct tm * timeinfo = localtime((const time_t *)&timestamp);
    char *datetime_str=OPENSSL_zalloc(DATETIME_SIZE);

    strftime(datetime_str, DATETIME_SIZE, "%Y-%m-%d %H:%M:%S", timeinfo);
    return datetime_str;
}


int review_feedback(const char * buf,size_t buf_size, const char ** error_str_pp){
    const char * res;
    result_feedback_t *feedback=_create_request(sizeof(result_feedback_t));
    get_with_va(buf,buf_size,4,&feedback->session_id,&feedback->user_name,&res,error_str_pp);
    return *res=='0'?0:1;
}

#endif