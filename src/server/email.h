#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
# define ACCOUNT "lyuzepeng.app@gmail.com"
# define FROM_EMAIL "lyuzepeng.app@gmail.com"
# define PASS_KEY "need stmp application key"
# define EMAIL_MAX_SIZE 1000
// 邮件内容结构
struct UploadData {
    const char *data;
    size_t size;
    size_t bytes_read;
};

// 读取邮件内容的回调函数
static size_t read_callback(void *ptr, size_t size, size_t nmemb, void *userp) {
    struct UploadData *upload = (struct UploadData *)userp;
    size_t max_size = size * nmemb;
    
    if(upload->bytes_read >= upload->size) {
        return 0;
    }
    
    size_t to_copy = upload->size - upload->bytes_read;
    if(to_copy > max_size) {
        to_copy = max_size;
    }
    
    memcpy(ptr, upload->data + upload->bytes_read, to_copy);
    upload->bytes_read += to_copy;
    
    return to_copy;
}

// 这里 token 需要追加'\0'
int send_email(const char * recipient, const char * token,size_t token_size){ 
    
    const char * token_=append_character(token,token_size,'\0');
    
    CURL *curl;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_ALL);

    curl = curl_easy_init();
    if(curl) {
        // 构建 RFC 2822 格式的邮件内容
        // const char *email_data = 
        //     "From: lyuzepeng.app@gmail.com\r\n"
        //     "To: lyuzepeng@gmail.com\r\n"
        //     "Subject: Test Email\r\n"
        //     "Content-Type: text/plain; charset=UTF-8\r\n"
        //     "\r\n"  // 空行分隔头部和正文
        //     "Hello, this is a test email.\r\n";
        
        char email_data[EMAIL_MAX_SIZE]={0};
        char * email_template="From: %s\r\n"
            "To: %s\r\n"
            "Subject: Test Email\r\n"
            "Content-Type: text/plain; charset=UTF-8\r\n"
            "\r\n"  // 空行分隔头部和正文
            "The account register token: %s\r\n";

        sprintf(email_data,email_template,FROM_EMAIL,recipient,token_);
        

        struct UploadData upload_ctx = {
            .data = email_data,
            .size = strlen(email_data),
            .bytes_read = 0
        };

        // 设置 SMTP 服务器（使用 smtps:// 表示 SSL）
        curl_easy_setopt(curl, CURLOPT_URL, "smtps://smtp.gmail.com:465");
        
        // 设置发件人
        curl_easy_setopt(curl, CURLOPT_MAIL_FROM, FROM_EMAIL);
        
        // 设置收件人列表
        struct curl_slist *recipient_ = NULL;
        recipient_ = curl_slist_append(recipient_, recipient);
        curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipient_);
        
        // 设置认证信息
        curl_easy_setopt(curl, CURLOPT_USERNAME, ACCOUNT);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, PASS_KEY); // 使用应用专用密码
        
        // 设置 SSL
        curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
        
        // 设置邮件内容
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
        curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        
        // 可选：启用详细输出用于调试
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

        printf("正在发送邮件...\n");
        res = curl_easy_perform(curl);
        
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {
            printf("邮件发送成功！\n");
        }

        // 清理
        curl_slist_free_all(recipient_);
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
    return 0;
}