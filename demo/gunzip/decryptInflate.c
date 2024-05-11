#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/md5.h>

#define SEED_LEN 32
#define KEY_LEN  16
void generate_key(const char *username, unsigned char *key)
{
    unsigned char seed[SEED_LEN];
    snprintf(seed, SEED_LEN, "%s:%ld", username, time(NULL));
    printf("seed:%s\n", seed);

    unsigned char md[MD5_DIGEST_LENGTH];
    MD5(seed, sizeof(seed), md);
    RAND_seed(md, sizeof(md));
    RAND_bytes(key, KEY_LEN);
}

//加密函数
char *encrypt_string(char *string)
{
    unsigned char key[KEY_LEN];

    //生成密钥
    generate_key("aa", &key);
    int i=0;
    for(; i<16; i++)
    {
        printf("%02x ", key[i]);
    }
    //利用key对string进行base64加密
    printf("str:%s\n", string);
}

void main()
{
    char base64_str[SEED_LEN];
    encrypt_string(base64_str);
}