//
//  main.c
//  aescompress
//
//  Created by Nian on 2022/4/26.
//
#include <stdio.h>
#include <string.h>  // for strlen
#include <assert.h>
#include "zlib.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/md5.h>

#ifndef u_char
#define u_char          unsigned char
#endif

#define  NGX_OK          0
#define  NGX_ERROR      -1

#if __BORLANDC__
typedef int                 intptr_t;
typedef u_int               uintptr_t;
#endif

typedef intptr_t        ngx_int_t;
typedef uintptr_t       ngx_uint_t;

#define AES_ENCODE_LEN(x) ((x/16 +1)*16)
#define ngx_base64_encoded_length(len)  (((len + 2) / 3) * 4)
#define ngx_base64_decoded_length(len)  (((len + 3) / 4) * 3)

typedef struct {
    size_t      len;
    u_char     *data;
} ngx_str_t;

static void
ngx_encode_base64_internal(ngx_str_t *dst, ngx_str_t *src, const u_char *basis,
    ngx_uint_t padding)
{
    u_char         *d, *s;
    size_t          len;

    len = src->len;
    s = src->data;
    d = dst->data;

    while (len > 2) {
        *d++ = basis[(s[0] >> 2) & 0x3f];
        *d++ = basis[((s[0] & 3) << 4) | (s[1] >> 4)];
        *d++ = basis[((s[1] & 0x0f) << 2) | (s[2] >> 6)];
        *d++ = basis[s[2] & 0x3f];

        s += 3;
        len -= 3;
    }

    if (len) {
        *d++ = basis[(s[0] >> 2) & 0x3f];

        if (len == 1) {
            *d++ = basis[(s[0] & 3) << 4];
            if (padding) {
                *d++ = '=';
            }

        } else {
            *d++ = basis[((s[0] & 3) << 4) | (s[1] >> 4)];
            *d++ = basis[(s[1] & 0x0f) << 2];
        }

        if (padding) {
            *d++ = '=';
        }
    }

    dst->len = d - dst->data;
}

static ngx_int_t
ngx_decode_base64_internal(ngx_str_t *dst, ngx_str_t *src, const u_char *basis)
{
    size_t          len;
    u_char         *d, *s;

    for (len = 0; len < src->len; len++) {
        if (src->data[len] == '=') {
            break;
        }

        if (basis[src->data[len]] == 77) {
            return NGX_ERROR;
        }
    }

    if (len % 4 == 1) {
        return NGX_ERROR;
    }

    s = src->data;
    d = dst->data;

    while (len > 3) {
        *d++ = (u_char) (basis[s[0]] << 2 | basis[s[1]] >> 4);
        *d++ = (u_char) (basis[s[1]] << 4 | basis[s[2]] >> 2);
        *d++ = (u_char) (basis[s[2]] << 6 | basis[s[3]]);

        s += 4;
        len -= 4;
    }

    if (len > 1) {
        *d++ = (u_char) (basis[s[0]] << 2 | basis[s[1]] >> 4);
    }

    if (len > 2) {
        *d++ = (u_char) (basis[s[1]] << 4 | basis[s[2]] >> 2);
    }

    dst->len = d - dst->data;

    return NGX_OK;
}


void
ngx_encode_base64(ngx_str_t *dst, ngx_str_t *src)
{
    static u_char   basis64[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    ngx_encode_base64_internal(dst, src, basis64, 1);
}


void
ngx_encode_base64url(ngx_str_t *dst, ngx_str_t *src)
{
    static u_char   basis64[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    ngx_encode_base64_internal(dst, src, basis64, 0);
}



ngx_int_t
ngx_decode_base64(ngx_str_t *dst, ngx_str_t *src)
{
    static u_char   basis64[] = {
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 62, 77, 77, 77, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 77, 77, 77, 77, 77,
        77,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 77, 77, 77, 77, 77,
        77, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 77, 77, 77, 77, 77,

        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77
    };

    return ngx_decode_base64_internal(dst, src, basis64);
}


ngx_int_t
ngx_decode_base64url(ngx_str_t *dst, ngx_str_t *src)
{
    static u_char   basis64[] = {
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 62, 77, 77,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 77, 77, 77, 77, 77,
        77,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 77, 77, 77, 77, 63,
        77, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 77, 77, 77, 77, 77,

        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77
    };

    return ngx_decode_base64_internal(dst, src, basis64);
}

/*
 * WebSec AES Function
 */
int Aes_decrypt(ngx_str_t *in, ngx_str_t *out, u_char *key)
{
    AES_KEY aes_enc_ctx;
    AES_set_decrypt_key(key, 128, &aes_enc_ctx);
    size_t i = 0;
    while (i < in->len) {
        AES_decrypt(in->data + i, out->data + i, &aes_enc_ctx);
        i += 16;
    }
    int lastpos = i - 1;
    u_char lastpad = out->data[lastpos];
    int pad_len;
    pad_len = lastpad;
    if (lastpad == 0) pad_len = 16;
    out->data[i - pad_len] = 0;
    out->len = i - pad_len;
    return 1;
}

int Aes_encrypt(ngx_str_t *in, ngx_str_t *out, u_char *key)
{
    AES_KEY aes_enc_ctx;
    AES_set_encrypt_key(key, 128, &aes_enc_ctx);
    int blocks = in->len / 16 + 1;
    int i;

    for (i = 0; i<blocks - 1; i++) {
        AES_encrypt(in->data + i * 16, out->data + i * 16, &aes_enc_ctx);
    }

    u_char tail[16] = {0};
    int left = in->len - i * 16;
    if (left > 0) {
        memcpy(tail, in->data + i * 16, left);
        memset(tail + left, 16 - left, 16 - left);
    } else if (left == 0) {
        memset(tail, 16, 16);
    }

    AES_encrypt(tail, out->data + i * 16, &aes_enc_ctx);

    return 1;

}

ngx_str_t genRandomString(int length)
{
    int flag, i;
    ngx_str_t string;
    static int isfisrt = 1;
    if (isfisrt) {
        isfisrt = 0;
        srand((unsigned)time(NULL));
    }
    string.data = malloc(length);

    for (i = 0; i < length; i++) {
        flag = rand() % 3;
        switch (flag) {
        case 0:
            string.data[i] = 'A' + rand() % 26;
            break;
        case 1:
            string.data[i] = 'a' + rand() % 26;
            break;
        case 2:
            string.data[i] = '0' + rand() % 10;
            break;
        default:
            string.data[i] = 'x';
            break;
        }
    }
    string.len = length;
    return string;
}

ngx_str_t str_encrypt(ngx_str_t in)
{
    printf( "[%d]in:%s\n", in.len, in.data);
    ngx_str_t hijack;
    ngx_str_t aes;
    ngx_str_t key;

    aes.len = AES_ENCODE_LEN(in.len);
    aes.data = malloc(aes.len);

    //key = ngx_string("W4n087I8e8301dd2");
    key.len = sizeof("W4n087I8e8301dd2") - 1;
    key.data = (u_char *)"W4n087I8e8301dd2";
    
    Aes_encrypt(&in, &aes, key.data);

    hijack.len = ngx_base64_encoded_length(aes.len) + 16;
    hijack.data = malloc(hijack.len);
    memcpy(hijack.data, key.data, 16);
    hijack.data += 16;
    hijack.len -= 16;
    ngx_encode_base64(&hijack, &aes);
    hijack.len += 16;
    hijack.data -= 16;
    printf( "%d ---- %s", hijack.len, hijack.data);
    return hijack;
}



int aes_128_ecb_encrypt(char *in, char *key, char *out, int length) {
    int ret = 0, len = 0, len1 = 0, len2 = 0;
    unsigned char *result = NULL;
    EVP_CIPHER_CTX *ctx;
    
    ctx = EVP_CIPHER_CTX_new();
    ret = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, (const unsigned char*)key, NULL);
    
    if (ret != 1) {
        printf("EVP_EncryptInit_ex error\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    result = (unsigned char *)malloc(AES_BLOCK_SIZE*640);

    ret = EVP_EncryptUpdate(ctx, result, &len1, (const unsigned char*)in, length);

    if (ret != 1) {
        printf("EVP_EncryptUpdate error\n");
        EVP_CIPHER_CTX_free(ctx);
        free(result);
        return 0;
    }
    ret = EVP_EncryptFinal_ex(ctx, result + len1, &len2);
    if (ret != 1) {
        printf("EVP_EncryptFinal_ex error\n");
        EVP_CIPHER_CTX_free(ctx);
        free(result);
        return 0;
    }

    while (len < (len1+len2)) {
        out[len] = result[len];
        len++;
    }
    EVP_CIPHER_CTX_free(ctx);
    free(result);
    return (len1+len2);
}

int get_str_len(const char *in) {
    int num = 0;
    if(in == NULL) {
        return 0;
    }
    while (!((*(in + num) == NULL) && (*(in + num + 1) == NULL) \
    && (*(in + num + 2) == NULL) && (*(in + num + 3) == NULL) \
    && (*(in + num + 4) == NULL)&& (*(in + num + 5) == NULL) \
    && (*(in + num + 6) == NULL)&& (*(in + num + 7) == NULL))) {
        num++;
    }
    return num;
}


int aes_128_ecb_decrypt(char *in, char *key, char *out) {
    int ret = 0, len = 0, len1 = 0, len2 = 0;
    unsigned char *result = NULL;
    
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    ret = EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, (const unsigned char*)key, NULL);
    if (ret != 1) {
        printf("EVP_DecryptInit_ex error\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    result = (unsigned char *)malloc(AES_BLOCK_SIZE*640);

    ret = EVP_DecryptUpdate(ctx, result, &len1, (const unsigned char*)in,get_str_len(in));//不可使用strlen求取，字符串中可能含有结束符等

    if (ret != 1) {
        printf("EVP_DecryptUpdate error\n");
        EVP_CIPHER_CTX_free(ctx);
        free(result);
        return 0;
    }
    ret = EVP_DecryptFinal_ex(ctx, result + len1, &len2);
    if (ret != 1) {
        printf("EVP_DecryptFinal_ex error\n");
        EVP_CIPHER_CTX_free(ctx);
        free(result);
        return 0;
    }
    while (len < (len1+len2)) {
        out[len] = result[len];
        len++;
    }
    EVP_CIPHER_CTX_free(ctx);
    free(result);
    return 1;
}

// base64 编码
char *base64_encode(const char *buffer, int length) {
    BIO *bmem = NULL;
    BIO *b64 = NULL;
    BUF_MEM *bptr;
    char *buff = NULL;
    
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, buffer, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    BIO_set_close(b64, BIO_NOCLOSE);

    buff = (char *)malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;
    BIO_free_all(b64);

    return buff;
}

// base64 解码
char *base64_decode(char *input, int length) {
    BIO *b64 = NULL;
    BIO *bmem = NULL;
    char *buffer = NULL;
    buffer = (char *)malloc(length);
    memset(buffer, 0, length);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf(input, length);
    bmem = BIO_push(b64, bmem);
    BIO_read(bmem, buffer, length);
    BIO_free_all(bmem);

    return buffer;
}

int md5_16(const char *src, char *out) {
    unsigned char c[MD5_DIGEST_LENGTH];
    int i = 0;
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, src, strlen(src));
    MD5_Final(c, &ctx);

    for (i = 0; i < MD5_DIGEST_LENGTH / 2; i++) {
        sprintf(out+i*2, "%02X", c[i+4]);
    }
    return 1;
}

// gzCompress: do the compressing
int gzCompress(const char *src, int srcLen, char *dest, int destLen)
{
    z_stream c_stream;
    int err = 0;
    int windowBits = 15;
    int GZIP_ENCODING = 16;

    if(src && srcLen > 0)
    {
        c_stream.zalloc = (alloc_func)0;
        c_stream.zfree = (free_func)0;
        c_stream.opaque = (voidpf)0;
        if(deflateInit2(&c_stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                    windowBits | GZIP_ENCODING, 8, Z_DEFAULT_STRATEGY) != Z_OK) return -1;
        c_stream.next_in  = (Bytef *)src;
        c_stream.avail_in  = srcLen;
        c_stream.next_out = (Bytef *)dest;
        c_stream.avail_out  = destLen;
        while (c_stream.avail_in != 0 && c_stream.total_out < destLen)
        {
            if(deflate(&c_stream, Z_NO_FLUSH) != Z_OK) return -1;
        }
            if(c_stream.avail_in != 0) return c_stream.avail_in;
        for (;;) {
            if((err = deflate(&c_stream, Z_FINISH)) == Z_STREAM_END) break;
            if(err != Z_OK) return -1;
        }
        if(deflateEnd(&c_stream) != Z_OK) return -1;
        return c_stream.total_out;
    }
    return -1;
}

// gzDecompress: do the decompressing
int gzDecompress(const char *src, int srcLen, const char *dst, int dstLen){
    z_stream strm;
    strm.zalloc=NULL;
    strm.zfree=NULL;
    strm.opaque=NULL;
     
    strm.avail_in = srcLen;
    strm.avail_out = dstLen;
    strm.next_in = (Bytef *)src;
    strm.next_out = (Bytef *)dst;
     
    int err=-1, ret=-1;
    err = inflateInit2(&strm, MAX_WBITS+16);
    if (err == Z_OK){
        err = inflate(&strm, Z_FINISH);
        if (err == Z_STREAM_END){
            ret = strm.total_out;
        }
        else{
            inflateEnd(&strm);
            return err;
        }
    }
    else{
        inflateEnd(&strm);
        return err;
    }
    inflateEnd(&strm);
    return err;
}

int main()
{
    char* src = "{\"api_id\":\"25008321459352675236199965506216\",\"app_sig\":\"d25748ff0840df6ae07c4b127de2c8aa7fd4bcd8\",\"has_clutch\":false,\"acceleration.z\":9.835997,\"acceleration.x\":-0.25124636,\"app_version\":1,\"acceleration.y\":0.23419751,\"has_lib_substrate_dvm\":false,\"mac_sha1\":\"e9ff5c024730db062c0b9deb993252ff334baacc\",\"gyroscope.change_count\":46,\"telephony.mnc\":1,\"app_version_code\":1,\"oem_name\":\"munch_munch_unknown_Redmi_1670476629000\",\"wifi.ip\":\"nil\",\"magnetic.delta.z\":37.893753,\"magnetic.delta.y\":1160.2876,\"magnetic.delta.x\":402.95627,\"acceleration.type\":true,\"magnetic.y\":1160.2876,\"magnetic.x\":402.95627,\"inet6_mac_sha1\":\"7589a39184241a0f0b80a15cf21e1a7a052a48bd\",\"telephony.sim_num\":\"nil\",\"telephony.mcc\":460,\"client_identity\":\"6e01f28d-1b2c-4118-b385-49c5499d3612\",\"userdata_created_time\":1671600966680,\"gps.mode\":\"gps\",\"telephony.is_dul_sim\":false,\"gyroscope.delta.y\":4.5813544E-4,\"gyroscope.delta.z\":1.5271181E-4,\"manufacture\":\"Xiaomi\",\"wifi.bssid\":\"nil\",\"has_cydia\":false,\"gyroscope.delta.x\":7.635591E-5,\"has_ipa_patch\":false,\"magnetic.z\":37.893753,\"is_rooted\":false,\"storage_size\":235722716,\"gravity.y\":0.23364198,\"app_version_name\":\"1.0\",\"gravity.x\":-0.2557401,\"gravity.z\":9.8005295,\"has_vpn\":false,\"app_sig_num\":1,\"gravity.delta.z\":9.8005295,\"gravity.delta.y\":0.23364198,\"gravity.delta.x\":-0.2557401,\"system_activation_time\":0,\"gyroscope.x\":7.635591E-5,\"acceleration.delta.z\":9.835997,\"acceleration.delta.y\":0.23419751,\"magnetic.change_count\":44,\"platform\":\"Android\",\"telephony.operator\":\"46001\",\"acceleration.delta.x\":-0.25124636,\"display_width\":1080,\"gyroscope.z\":1.5271181E-4,\"gyroscope.y\":4.5813544E-4,\"sdk_sw_ver\":33,\"has_lib_substrate\":false,\"gravity.change_count\":43,\"sdk_version\":33,\"acceleration.change_count\":45,\"is_emulator\":false,\"app_list\":\"[{name='传送门', packageName='com.miui.contentextension', version='2.5.74', isSystemApp='true'}, {name='QColor', packageName='com.qualcomm.qti.qcolor', version='13', isSystemApp='true'}, {name='Android Services Library', packageName='com.google.android.ext.services', version='t_frc_ext_330443000', isSystemApp='true'}, {name='Android AdServices', packageName='com.android.adservices.api', version='13', isSystemApp='true'}, {name='电话和短信存储', packageName='com.android.providers.telephony', version='13', isSystemApp='true'}, {name='Dynamic System Updates', packageName='com.android.dynsystem', version='13', isSystemApp='true'}, {name='电量和性能', packageName='com.miui.powerkeeper', version='4.2.00', isSystemApp='true'}, {name='com.miui.qr.InfoApplication', packageName='com.miui.qr', version='2022_11_07_10_05', isSystemApp='true'}, {name='MIUI Privacy Components', packageName='com.miui.privacycomputing', version='1.0.3', isSystemApp='true'}, {name='日历存储', packageName='com.android.providers.calendar', version='10.0.5.5', isSystemApp='true'}, {name='应用程序扩展服务', packageName='com.miui.contentcatcher', version='1.0.002', isSystemApp='true'}, {name='android.miui.home.launcher.res', packageName='android.miui.home.launcher.res', version='13', isSystemApp='true'}, {name='com.android.providers.media', packageName='com.android.providers.media', version='13', isSystemApp='true'}, {name='投屏', packageName='com.milink.service', version='14.0.1.4', isSystemApp='true'}, {name='RegService', packageName='com.miui.dmregservice', version='3.0', isSystemApp='true'}, {name='com.qti.service.colorservice', packageName='com.qti.service.colorservice', version='1.0', isSystemApp='true'}, {name='QtiWifiService', packageName='com.qualcomm.qti.server.qtiwifi', version='13', isSystemApp='true'}, {name='小米帐号', packageName='com.xiaomi.account', version='R-22.11.30.00', isSystemApp='true'}, {name='com.android.wallpapercropper', packageName='com.android.wallpapercropper', version='13', isSystemApp='true'}, {name='CatchLog', packageName='com.bsp.catchlog', version='13', isSystemApp='true'}, {name='相机标定', packageName='com.xiaomi.cameratools', version='22.10.20.0', isSystemApp='true'}, {name='系统界面组件', packageName='miui.systemui.plugin', version='13.1.1.60.0', isSystemApp='true'}, {name='小米互联通信服务', packageName='com.xiaomi.mi_connect_service', version='2.12.200', isSystemApp='true'}, {name='运营商服务', packageName='com.qualcomm.qti.autoregistration', version='3.0', isSystemApp='true'}, {name='com.xiaomi.micloudsdk.SdkApplication', packageName='com.xiaomi.micloud.sdk', version='2.0.0.0', isSystemApp='true'}, {name='应用包管理组件', packageName='com.miui.packageinstaller', version='5.0.6.2-20221107', isSystemApp='true'}, {name='系统更新', packageName='com.android.updater', version='8.0.2', isSystemApp='true'}, {name='com.xiaomi.bluetooth.rro.device.config.overlay', packageName='com.xiaomi.bluetooth.rro.device.config.overlay', version='1.0', isSystemApp='true'}, {name='外部存储设备', packageName='com.android.externalstorage', version='13', isSystemApp='true'}, {name='com.qualcomm.uimremoteclient', packageName='com.qualcomm.uimremoteclient', version='13', isSystemApp='true'}, {name='Bokeh', packageName='com.miui.extraphoto', version='1.7.4.0', isSystemApp='true'}, {name='系统服务组件', packageName='com.miui.securityadd', version='9.11.23-221117.0.1', isSystemApp='true'}, {name='uceShimService', packageName='com.qualcomm.qti.uceShimService', version='13', isSystemApp='true'}, {name='配套设备管理器', packageName='com.android.companiondevicemanager', version='13', isSystemApp='true'}, {name='相册', packageName='com.miui.gallery', version='3.5.1.0', isSystemApp='true'}, {name='搜索', packageName='com.android.quicksearchbox', version='9.7.0.2', isSystemApp='true'}, {name='MmsService', packageName='com.android.mms.service', version='13', isSystemApp='true'}, {name='下载管理程序', packageName='com.android.providers.downloads', version='122.10.14.800001', isSystemApp='true'}, {name='米币支付', packageName='com.xiaomi.payment', version='2.4.3', isSystemApp='true'}, {name='网络管理器', packageName='com.android.networkstack.inprocess', version='13', isSystemApp='true'}, {name='手机管家', packageName='com.miui.securitycenter', version='7.3.5-221203.0.1', isSystemApp='true'}, {name='CACertApp', packageName='vendor.qti.hardware.cacert.server', version='1.0', isSystemApp='true'}, {name='com.qualcomm.qti.telephonyservice', packageName='com.qualcomm.qti.telephonyservice', version='13', isSystemApp='true'}, {name='性能模式', packageName='com.qualcomm.qti.performancemode', version='13', isSystemApp='true'}, {name='浏览器', packageName='com.android.browser', version='17.0.18', isSystemApp='true'}, {name='智能服务', packageName='com.miui.systemAdSolution', version='2022.09.21.06-release', isSystemApp='true'}, {name='小爱翻译', packageName='com.xiaomi.aiasst.vision', version='3.2.7', isSystemApp='true'}, {name='小米智能卡', packageName='com.miui.tsmclient', version='22.12.09.1.o', isSystemApp='true'}, {name='RideMode Recording list', packageName='com.qualcomm.qti.ridemodeaudio', version='13', isSystemApp='true'}, {name='vendor.qti.iwlan', packageName='vendor.qti.iwlan', version='1.0', isSystemApp='true'}, {name='com.qualcomm.uimremoteserver', packageName='com.qualcomm.uimremoteserver', version='13', isSystemApp='true'}, {name='MIUI安全组件', packageName='com.miui.guardprovider', version='1.4.8', isSystemApp='true'}, {name='android.qvaoverlay.common', packageName='android.qvaoverlay.common', version='13', isSystemApp='true'}, {name='Google Play Store', packageName='com.android.vending', version='25.8.20-21 [0] [PR] 379052828', isSystemApp='true'}, {name='PacProcessor', packageName='com.android.pacprocessor', version='13', isSystemApp='true'}, {name='备份', packageName='com.miui.backup', version='6.4.0.4', isSystemApp='true'}, {name='com.android.settings.overlay.miui', packageName='com.android.settings.overlay.miui', version='13', isSystemApp='true'}, {name='通知管理', packageName='com.miui.notification', version='1.1.4.81', isSystemApp='true'}, {name='android.overlay.common', packageName='android.overlay.common', version='13', isSystemApp='true'}, {name='com.miui.system.overlay', packageName='com.miui.system.overlay', version='13', isSystemApp='true'}, {name='MiCloudSync', packageName='com.miui.micloudsync', version='1.12.0.0.10', isSystemApp='true'}, {name='弹幕通知', packageName='com.xiaomi.barrage', version='1.1.0', isSystemApp='true'}, {name='MIUI质量服务', packageName='com.miui.daemon', version='2.0', isSystemApp='true'}, {name='NetworkStackOverlay', packageName='com.android.networkstack.overlay', version='13', isSystemApp='true'}, {name='证书安装程序', packageName='com.android.certinstaller', version='13', isSystemApp='true'}, {name='我的服务', packageName='com.miui.vipservice', version='1.3.0', isSystemApp='true'}, {name='com.android.carrierconfig', packageName='com.android.carrierconfig', version='1.0.0', isSystemApp='true'}, {name='com.android.carrierconfig.overlay.miui', packageName='com.android.carrierconfig.overlay.miui', version='13', isSystemApp='true'}, {name='WAPI证书', packageName='com.wapi.wapicertmanage', version='13', isSystemApp='true'}, {name='游戏高能时刻', packageName='com.xiaomi.migameservice', version='0.5.6', isSystemApp='true'}, {name='com.qti.qualcomm.datastatusnotification', packageName='com.qti.qualcomm.datastatusnotification', version='13', isSystemApp='true'}, {name='Android 系统', packageName='android', version='13', isSystemApp='true'}, {name='小米换机', packageName='com.miui.huanji', version='3.9.7', isSystemApp='false'}, {name='com.miui.settings.rro.device.hide.statusbar.overlay', packageName='com.miui.settings.rro.device.hide.statusbar.overlay', version='1.0', isSystemApp='true'}, {name='Wfd Service', packageName='com.qualcomm.wfd.service', version='2.0', isSystemApp='true'}, {name='快应用服务框架', packageName='com.miui.hybrid', version='1.10.0.0', isSystemApp='true'}, {name='android.miui.overlay', packageName='android.miui.overlay', version='13', isSystemApp='true'}, {name='MConnService', packageName='com.miui.vsimcore', version='1.0.5', isSystemApp='true'}, {name='安全核心组件', packageName='com.miui.securitycore', version='25', isSystemApp='true'}, {name='CarWith', packageName='com.miui.carlink', version='1.1.0-20221110', isSystemApp='true'}, {name='UI信息工具', packageName='com.miui.uireporter', version='1.0.2', isSystemApp='true'}, {name='设备信息', packageName='com.qti.qualcomm.deviceinfo', version='13', isSystemApp='true'}, {name='Eid-Service', packageName='com.rongcard.eid', version='13', isSystemApp='true'}, {name='Android S Easter Egg', packageName='com.android.egg', version='1.0', isSystemApp='true'}, {name='MTP 主机', packageName='com.android.mtp', version='13', isSystemApp='true'}, {name='NFC服务', packageName='com.android.nfc', version='13', isSystemApp='true'}, {name='com.android.ons', packageName='com.android.ons', version='13', isSystemApp='true'}, {name='USIM卡应用', packageName='com.android.stk', version='13', isSystemApp='true'}, {name='com.android.backupconfirm', packageName='com.android.backupconfirm', version='13', isSystemApp='true'}, {name='小米SIM卡激活服务', packageName='com.xiaomi.simactivate.service', version='BETA-22.12.05', isSystemApp='true'}, {name='指纹测试', packageName='com.goodix.gftest', version='1.1.01', isSystemApp='true'}, {name='常用语', packageName='com.miui.phrase', version='3.2.5', isSystemApp='true'}, {name='音乐', packageName='com.miui.player', version='4.10.0.9', isSystemApp='true'}, {name='服务与反馈', packageName='com.miui.miservice', version='13.0.3.23', isSystemApp='true'}, {name='OtaProvision', packageName='com.miui.otaprovision', version='13.0.12.05.1', isSystemApp='true'}, {name='开机引导', packageName='com.android.provision', version='13', isSystemApp='true'}, {name='org.codeaurora.ims', packageName='org.codeaurora.ims', version='1.0', isSystemApp='true'}, {name='意图过滤器验证服务', packageName='com.android.statementservice', version='1.0', isSystemApp='true'}, {name='android.overlay.target', packageName='android.overlay.target', version='13', isSystemApp='true'}, {name='com.miui.internal.app.SystemApplication', packageName='com.miui.system', version='1.15.0.0', isSystemApp='true'}, {name='com.android.overlay.systemui', packageName='com.android.overlay.systemui', version='1.0', isSystemApp='true'}, {name='com.android.incallui.overlay', packageName='com.android.incallui.overlay', version='1.0', isSystemApp='true'}, {name='com.miui.translation.kingsoft', packageName='com.miui.translation.kingsoft', version='1.0', isSystemApp='true'}, {name='com.android.managedprovisioning.overlay', packageName='com.android.managedprovisioning.overlay', version='13', isSystemApp='true'}, {name='com.android.overlay.gmscontactprovider', packageName='com.android.overlay.gmscontactprovider', version='1.0', isSystemApp='true'}, {name='com.miui.catcherpatch.BaseApplication', packageName='com.miui.catcherpatch', version='20180613.01', isSystemApp='true'}, {name='com.miui.miwallpaper.overlay.customize', packageName='com.miui.miwallpaper.overlay.customize', version='13', isSystemApp='true'}, {name='维修模式', packageName='com.miui.maintenancemode', version='3.1.0', isSystemApp='true'}, {name='com.android.overlay.gmssettingprovider', packageName='com.android.overlay.gmssettingprovider', version='1.0', isSystemApp='true'}, {name='com.miui.systemui.devices.overlay', packageName='com.miui.systemui.devices.overlay', version='1.0', isSystemApp='true'}, {name='com.qualcomm.qti.dynamicddsservice', packageName='com.qualcomm.qti.dynamicddsservice', version='1.0', isSystemApp='true'}, {name='万象息屏', packageName='com.miui.aod', version='RELEASE-2.11.1012-11231939', isSystemApp='true'}, {name='CIT', packageName='com.miui.cit', version='0.1.1-SNAPSHOT', isSystemApp='true'}, {name='com.miui.rom', packageName='com.miui.rom', version='1.11.0.0', isSystemApp='true'}, {name='textaction', packageName='com.miuix.editor', version='13', isSystemApp='true'}, {name='com.qualcomm.qcrilmsgtunnel', packageName='com.qualcomm.qcrilmsgtunnel', version='13', isSystemApp='true'}, {name='设置存储', packageName='com.android.providers.settings', version='13', isSystemApp='true'}, {name='MiuiVpnSdkManager', packageName='com.miui.vpnsdkmanager', version='21', isSystemApp='true'}, {name='com.android.sharedstoragebackup', packageName='com.android.sharedstoragebackup', version='13', isSystemApp='true'}, {name='融合位置服务', packageName='com.xiaomi.location.fused', version='2.0.12', isSystemApp='true'}, {name='com.miui.miinput.MiInputApplication', packageName='com.miui.miinput', version='ALPHA-1.0.2-2210082133', isSystemApp='true'}, {name='智能助理', packageName='com.miui.personalassistant', version='5.5.51-1021', isSystemApp='true'}, {name='音质音效', packageName='com.miui.misound', version='2.0', isSystemApp='true'}, {name='com.android.wifi.resources.overlay.common', packageName='com.android.wifi.resources.overlay.common', version='13', isSystemApp='true'}, {name='com.google.android.overlay.modules.ext.services', packageName='com.google.android.overlay.modules.ext.services', version='1.0', isSystemApp='true'}, {name='com.android.systemui.gesture.line.overlay', packageName='com.android.systemui.gesture.line.overlay', version='1.0', isSystemApp='true'}, {name='用户反馈', packageName='com.miui.bugreport', version='3.3.15.21', isSystemApp='true'}, {name='SecureElementApplication', packageName='com.android.se', version='13', isSystemApp='true'}, {name='输入设备', packageName='com.android.inputdevices', version='13', isSystemApp='true'}, {name='FIDO UAF1.0 ASM', packageName='com.fido.asm', version='1.0.220801.1', isSystemApp='true'}, {name='系统打印服务', packageName='com.android.bips', version='13', isSystemApp='true'}, {name='文件管理', packageName='com.android.fileexplorer', version='4.3.6.7', isSystemApp='true'}, {name='语音唤醒', packageName='com.miui.voicetrigger', version='v-5.4.0.3-qcom', isSystemApp='true'}, {name='自动连招', packageName='com.xiaomi.macro', version='2.2.4.S', isSystemApp='true'}, {name='com.android.systemui.overlay.miui', packageName='com.android.systemui.overlay.miui', version='13', isSystemApp='true'}, {name='com.android.settings.overlay.common', packageName='com.android.settings.overlay.common', version='13', isSystemApp='true'}, {name='com.google.android.overlay.gmsconfig', packageName='com.google.android.overlay.gmsconfig', version='1.0', isSystemApp='true'}, {name='com.android.overlay.gmssettings', packageName='com.android.overlay.gmssettings', version='1.0', isSystemApp='true'}, {name='小米云备份', packageName='com.miui.cloudbackup', version='1.12.1.5.30', isSystemApp='true'}, {name='com.miui.face.overlay.miui', packageName='com.miui.face.overlay.miui', version='13', isSystemApp='true'}, {name='com.android.cellbroadcastreceiver', packageName='com.android.cellbroadcastreceiver', version='R-initial', isSystemApp='true'}, {name='钱包', packageName='com.mipay.wallet', version='6.42.0.4425.2025', isSystemApp='true'}, {name='通话管理', packageName='com.android.server.telecom', version='13', isSystemApp='true'}, {name='通话管理', packageName='com.android.server.telecom.overlay.miui', version='13', isSystemApp='true'}, {name='Cell Broadcast Service', packageName='com.android.cellbroadcastservice', version='13', isSystemApp='true'}, {name='XiaoaiRecommendation', packageName='com.xiaomi.aireco', version='0.1.1', isSystemApp='true'}, {name='密钥链', packageName='com.android.keychain', version='13', isSystemApp='true'}, {name='QDCM-FF', packageName='com.qti.snapdragon.qdcm_ff', version='1.0', isSystemApp='true'}, {name='com.android.wifi.resources.overlay.target', packageName='com.android.wifi.resources.overlay.target', version='13', isSystemApp='true'}, {name='相机', packageName='com.android.camera', version='4.5.001520.3', isSystemApp='true'}, {name='小米服务框架', packageName='com.xiaomi.xmsf', version='6.0.5', isSystemApp='true'}, {name='com.miui.miwallpaper.wallpaperoverlay.config.overlay', packageName='com.miui.miwallpaper.wallpaperoverlay.config.overlay', version='1.0', isSystemApp='true'}, {name='小米互传', packageName='com.miui.mishare.connectivity', version='2.12.0', isSystemApp='true'}, {name='Google Play 服务', packageName='com.google.android.gms', version='22.49.13 (190400-493924051)', isSystemApp='true'}, {name='Google 服务框架', packageName='com.google.android.gsf', version='13-8768315', isSystemApp='true'}, {name='com.android.phone.overlay.common', packageName='com.android.phone.overlay.common', version='13', isSystemApp='true'}, {name='com.android.carrierconfig.overlay.common', packageName='com.android.carrierconfig.overlay.common', version='13', isSystemApp='true'}, {name='Call Log Backup\\/Restore', packageName='com.android.calllogbackup', version='13', isSystemApp='true'}, {name='自由窗口', packageName='com.miui.freeform', version='13', isSystemApp='true'}, {name='android.aosp.overlay', packageName='android.aosp.overlay', version='13', isSystemApp='true'}, {name='com.android.systemui.overlay.common', packageName='com.android.systemui.overlay.common', version='13', isSystemApp='true'}, {name='CameraExtensionsProxy', packageName='com.android.cameraextensions', version='13', isSystemApp='true'}, {name='Xiaomi Service Framework Keeper', packageName='com.xiaomi.xmsfkeeper', version='1.0.3', isSystemApp='true'}, {name='com.android.server.telecom.overlay.common', packageName='com.android.server.telecom.overlay.common', version='13', isSystemApp='true'}, {name='com.android.localtransport', packageName='com.android.localtransport', version='13', isSystemApp='true'}, {name='运营商默认应用', packageName='com.android.carrierdefaultapp', version='13', isSystemApp='true'}, {name='com.miui.wallpaper.overlay.customize', packageName='com.miui.wallpaper.overlay.customize', version='13', isSystemApp='true'}, {name='Usable Power Mode', packageName='com.qualcomm.qti.powersavemode', version='13', isSystemApp='true'}, {name='com.qualcomm.qti.remoteSimlockAuth', packageName='com.qualcomm.qti.remoteSimlockAuth', version='13', isSystemApp='true'}, {name='查找设备', packageName='com.xiaomi.finddevice', version='13', isSystemApp='true'}, {name='com.qualcomm.qti.devicestatisticsservice', packageName='com.qualcomm.qti.devicestatisticsservice', version='13', isSystemApp='true'}, {name='ProxyHandler', packageName='com.android.proxyhandler', version='13', isSystemApp='true'}, {name='Joyose', packageName='com.xiaomi.joyose', version='2.2.48', isSystemApp='true'}, {name='com.qualcomm.qti.workloadclassifier', packageName='com.qualcomm.qti.workloadclassifier', version='13', isSystemApp='true'}, {name='小米智能卡网页组件', packageName='com.miui.nextpay', version='22.12.09.1', isSystemApp='true'}, {name='小米视频', packageName='com.miui.video', version='v2022120290(MiVideo-UN)', isSystemApp='true'}, {name='WMService', packageName='com.miui.wmsvc', version='1.0.13', isSystemApp='true'}, {name='com.android.overlay.cngmstelecomm', packageName='com.android.overlay.cngmstelecomm', version='1.0', isSystemApp='true'}, {name='com.android.providers.settings.overlay', packageName='com.android.providers.settings.overlay', version='13', isSystemApp='true'}, {name='com.android.phone.overlay.miui', packageName='com.android.phone.overlay.miui', version='13', isSystemApp='true'}, {name='应用商店', packageName='com.xiaomi.market', version='4.44.10', isSystemApp='true'}, {name='小米设置', packageName='com.xiaomi.misettings', version='2.9.9.30', isSystemApp='true'}, {name='MIUI+ Beta版', packageName='com.xiaomi.mirror', version='3.7.44.a', isSystemApp='true'}, {name='com.miui.translationservice', packageName='com.miui.translationservice', version='1.0', isSystemApp='true'}, {name='小米云服务', packageName='com.miui.cloudservice', version='1.12.0.0.30', isSystemApp='true'}, {name='工作设置', packageName='com.android.managedprovisioning', version='13', isSystemApp='true'}, {name='智慧生活', packageName='com.miui.hybrid.accessory', version='1.4.3', isSystemApp='true'}, {name='Sensor Test Tool', packageName='com.fingerprints.sensortesttool', version='3.54', isSystemApp='true'}, {name='Polaris', packageName='com.xiaomi.gnss.polaris', version='2022.08.30.1', isSystemApp='true'}, {name='录音助手', packageName='com.miui.audiomonitor', version='13', isSystemApp='true'}, {name='otrpbroker', packageName='com.xiaomi.otrpbroker', version='1.0.220829', isSystemApp='true'}, {name='com.miui.translation.xmcloud', packageName='com.miui.translation.xmcloud', version='1.1', isSystemApp='true'}, {name='悬浮球', packageName='com.miui.touchassistant', version='9.0.4.5.1', isSystemApp='true'}, {name='鲁班(MTB)V3.9', packageName='com.xiaomi.mtb', version='13', isSystemApp='true'}, {name='GPU 驱动更新', packageName='com.xiaomi.ugd', version='1.2.0', isSystemApp='true'}, {name='com.xiaomi.NetworkBoost', packageName='com.xiaomi.NetworkBoost', version='13', isSystemApp='true'}, {name='com.miui.settings.rro.device.type.overlay', packageName='com.miui.settings.rro.device.type.overlay', version='1.0', isSystemApp='true'}, {name='devauth', packageName='com.xiaomi.devauth', version='1.0.220812', isSystemApp='true'}, {name='壁纸', packageName='com.miui.miwallpaper', version='1.8.2a', isSystemApp='true'}, {name='小米安全键盘', packageName='com.miui.securityinputmethod', version='2.0.7', isSystemApp='true'}, {name='com.android.systemui.navigation.bar.overlay', packageName='com.android.systemui.navigation.bar.overlay', version='1.0', isSystemApp='true'}, {name='MIUI Bluetooth', packageName='com.xiaomi.bluetooth', version='13', isSystemApp='true'}, {name='网络位置服务', packageName='com.xiaomi.metoknlp', version='5.0.2', isSystemApp='true'}, {name='com.google.android.cellbroadcastservice.overlay.miui', packageName='com.google.android.cellbroadcastservice.overlay.miui', version='13', isSystemApp='true'}, {name='存储空间管理器', packageName='com.android.storagemanager', version='13', isSystemApp='true'}, {name='Analytics', packageName='com.miui.analytics', version='5.4.0', isSystemApp='true'}, {name='设置', packageName='com.android.settings', version='13', isSystemApp='true'}, {name='CneApp', packageName='com.qualcomm.qti.cne', version='1.0', isSystemApp='true'}, {name='com.qualcomm.qti.lpa', packageName='com.qualcomm.qti.lpa', version='13', isSystemApp='true'}, {name='com.qualcomm.qti.uim', packageName='com.qualcomm.qti.uim', version='13', isSystemApp='true'}, {name='Tethering', packageName='com.android.networkstack.tethering.inprocess', version='13', isSystemApp='true'}, {name='com.modemdebug', packageName='com.modemdebug', version='3.0', isSystemApp='true'}, {name='LocationServices', packageName='com.qualcomm.location', version='20221017', isSystemApp='true'}, {name='com.miui.voiceassistoverlay', packageName='com.miui.voiceassistoverlay', version='2.0', isSystemApp='true'}, {name='小米无障碍', packageName='com.miui.accessibility', version='5.2.3', isSystemApp='true'}, {name='com.qualcomm.qti.uimGbaApp', packageName='com.qualcomm.qti.uimGbaApp', version='13', isSystemApp='true'}, {name='com.qti.diagservices', packageName='com.qti.diagservices', version='13', isSystemApp='true'}, {name='com.miui.systemui.carriers.overlay', packageName='com.miui.systemui.carriers.overlay', version='1.0', isSystemApp='true'}, {name='com.miui.systemui.overlay.devices.android', packageName='com.miui.systemui.overlay.devices.android', version='1.0', isSystemApp='true'}, {name='VpnDialogs', packageName='com.android.vpndialogs', version='13', isSystemApp='true'}, {name='小爱语音', packageName='com.miui.voiceassist', version='6.0.4.2215', isSystemApp='true'}, {name='电话服务', packageName='com.android.phone', version='13', isSystemApp='true'}, {name='com.android.overlay.gmstelephony', packageName='com.android.overlay.gmstelephony', version='1.0', isSystemApp='true'}, {name='Shell', packageName='com.android.shell', version='13', isSystemApp='true'}, {name='com.android.wallpaperbackup', packageName='com.android.wallpaperbackup', version='13', isSystemApp='true'}, {name='My Application', packageName='com.example.myapplication', version='1.0', isSystemApp='false'}, {name='存储已屏蔽的号码', packageName='com.android.providers.blockednumber', version='13', isSystemApp='true'}, {name='截屏', packageName='com.miui.screenshot', version='RELEASE-1.4.31-11140917', isSystemApp='true'}, {name='com.android.overlay.gmstelecomm', packageName='com.android.overlay.gmstelecomm', version='1.0', isSystemApp='true'}, {name='用户字典', packageName='com.android.providers.userdictionary', version='13', isSystemApp='true'}, {name='媒体存储设备', packageName='com.android.providers.media.module', version='13', isSystemApp='true'}, {name='急救信息', packageName='com.android.emergency', version='13', isSystemApp='true'}, {name='XRCB', packageName='com.qualcomm.qti.xrcb', version='13', isSystemApp='true'}, {name='一体化位置信息', packageName='com.android.location.fused', version='13', isSystemApp='true'}, {name='时钟', packageName='com.android.deskclock', version='13.53.0', isSystemApp='true'}, {name='系统界面', packageName='com.android.systemui', version='20220714.0', isSystemApp='true'}, {name='com.miui.core.internal.services', packageName='com.miui.core.internal.services', version='2.0', isSystemApp='true'}, {name='com.android.wifi.resources.xiaomi', packageName='com.android.wifi.resources.xiaomi', version='1.0', isSystemApp='true'}, {name='配置拨号器', packageName='com.qualcomm.qti.confdialer', version='13', isSystemApp='true'}, {name='关机闹钟', packageName='com.qualcomm.qti.poweroffalarm', version='13', isSystemApp='true'}, {name='com.google.android.cellbroadcastreceiver.overlay.miui', packageName='com.google.android.cellbroadcastreceiver.overlay.miui', version='13', isSystemApp='true'}, {name='com.qti.phone', packageName='com.qti.phone', version='13', isSystemApp='true'}, {name='权限控制器', packageName='com.android.permissioncontroller', version='33 system image', isSystemApp='true'}, {name='主题壁纸', packageName='com.android.thememanager', version='3.9.6.7', isSystemApp='true'}, {name='系统跟踪', packageName='com.android.traceur', version='1.0', isSystemApp='true'}, {name='SecurityOnetrackService', packageName='com.xiaomi.security.onetrack', version='1.0.220801', isSystemApp='true'}, {name='权限管理服务', packageName='com.lbe.security.miui', version='1.8.3', isSystemApp='true'}, {name='QCC', packageName='com.qti.qcc', version='QCC13.0-20220731-05a6cdbc', isSystemApp='true'}, {name='com.android.ondevicepersonalization.services', packageName='com.android.ondevicepersonalization.services', version='T-initial', isSystemApp='true'}, {name='com.qualcomm.qtil.btdsda', packageName='com.qualcomm.qtil.btdsda', version='13', isSystemApp='true'}, {name='蓝牙', packageName='com.android.bluetooth', version='13', isSystemApp='true'}, {name='com.qualcomm.timeservice', packageName='com.qualcomm.timeservice', version='13', isSystemApp='true'}, {name='com.qualcomm.atfwd', packageName='com.qualcomm.atfwd', version='13', isSystemApp='true'}, {name='com.qualcomm.embms', packageName='com.qualcomm.embms', version='1.0', isSystemApp='true'}, {name='联系人存储', packageName='com.android.providers.contacts', version='13', isSystemApp='true'}, {name='vendor.qti.imsrcs', packageName='vendor.qti.imsrcs', version='13', isSystemApp='true'}, {name='CaptivePortalLogin', packageName='com.android.captiveportallogin', version='s_aml_319999900', isSystemApp='true'}, {name='com.android.stk.overlay.miui', packageName='com.android.stk.overlay.miui', version='13', isSystemApp='true'}, {name='com.miui.settings.rro.device.config.overlay', packageName='com.miui.settings.rro.device.config.overlay', version='1.0', isSystemApp='true'}, {name='com.android.cellbroadcastreceiver.overlay.common', packageName='com.android.cellbroadcastreceiver.overlay.common', version='13', isSystemApp='true'}, {name='MiuiBiometric', packageName='com.miui.face', version='1.0.2', isSystemApp='true'}, {name='系统桌面', packageName='com.miui.home', version='RELEASE-4.39.9.5826-12141201', isSystemApp='true'}, {name='小爱通话', packageName='com.xiaomi.aiasst.service', version='5.1.73', isSystemApp='true'}, {name='小米数字钥匙框架', packageName='com.xiaomi.digitalkey', version='13.0.8', isSystemApp='true'}]\",\"wifi.ssid\":\"nil\",\"os_version\":\"4.19.157-perf-g9e936133ce1e\",\"sdk_commit_id\":1670476629000,\"has_dyld_insert\":false,\"app_name\":2131755036,\"app_installed_time\":1671600966680,\"display_height\":2400,\"os_name\":\"Linux\",\"battery_capacity\":4500,\"inet4_mac_sha1\":\"107398597e63af831505d0192e73dd04feeae006\",\"screen_rotation\":0}";
    int size_src = strlen(src);
    char* compressed = malloc(size_src*2);
    memset(compressed, 0, size_src*2);
//    printf("to compress src: %s\n", src);
    printf("to compress src size: %d\n", size_src);

    int gzSize = gzCompress(src, size_src, compressed, size_src*2);
    if (gzSize <= 0)
    {
        printf("compress error.\n");
        return -1;
    }
    printf("compressed: ");
    int i = 0;
    printf("%s\n", compressed);
    for (; i<gzSize; ++i)
    {
        printf("%02x ", compressed[i]);
    }
    printf("\ncompressed size: %d\n", gzSize);

    // 加密部分
    ngx_str_t enc;
    enc.data = compressed;
    enc.len  = gzSize;
    
    
    
    str_encrypt(enc);
//    nAESEncryptLen = aes_128_ecb_encrypt(compressed, strMd516, strAESEncrypt, gzSize);
//    strBase64Encrypt = base64_encode(strAESEncrypt, nAESEncryptLen);
//    printf("strBase64Encrypt: %s%s\n", strMd516, strBase64Encrypt);

    // 解密部分
//    pStrBase64Decrypt = base64_decode(strBase64Encrypt, strlen(strBase64Encrypt));
//    if (aes_128_ecb_decrypt(pStrBase64Decrypt, strMd516, strAESDecrypt) == 1) {
//        printf("aes_128_ecb_decrypt OK\n");
//        printf("strAESDecrypt passwd is: %s\n", strAESDecrypt);
//        for (i = 0; i<gzSize; ++i)
//        {
//            printf("%02x ", strAESDecrypt[i]);
//        }
//    }
    
//    memcpy(strAESDecrypt, compressed, gzSize);
//    char* uncompressed = malloc(size_src*2);
//    memset(uncompressed, 0, size_src*2);
    
//    char str[4096] = "CpfJNEj5268d41c81wCRx4oUgmryVnKir5A89fiQl9of2asJ6ixx6ZI495SvNKMqQEaEUNhsLVvpunxvYRZzjH9iHr3NGESE31BIUQ6T2JllfpjAnu0I4uvJ4CT8x73jnQlj7x1CBTVh7YiQqIErT3P8u_OK2AzXPGQ.BVIIdulmdsXyxUHLTjc94SIKDVYubVBKhXI8TF.gWVLN_QPmPSYvRo9BKxU_fpS2rZkZvRfKkM2sNAlKLWyDHqT48ctMUzycsA0SLOC7eUGubWjqWHXXbmEOj2BdiMGHhsiNxcqScgcwQ_9oVKP9UKZdO0xLa5W0YncUci8W_S5SZ2L7U47p4DWdBt_uWfUwZNnObCnq.7a9Ni6.LjaMVRrjBhKt.g4DFzE6uRYZAoezshA58vjqwmg9VMSTTSUknWgdtE2vMVpZwpXSSmsO60k3RBioLX96I6jdHc41WNaaxJDvgSPKhKO54GEOr3R0hK1dq7qHRA_CClaKhiXHg2Gdm3ufUWgpKe8wxVkZeBKmG5mcr2Dc0w5esel64PGt4l9BbhP1t83LBfn2KDhCQPHlp_xEyWHPOH9r6l6wVY1M781eLuXM_5VkZOb2hsFvA4ks.dCt9tYybuFJ1Fih3vjP7qUhZAjC7OIK9ZdMIjnZ3C2wM6bIa5qRpYDgxznjRKYz7Gt6x0xGZKrcQyJ8AN7N39h6el9qsk5Ih7aFUdMJYcbT9v5T2DJ8FTetNsPy3DNDt0nl7sdn7WEYDK23PDalf9HPzs25TB4bHZhNedZ7XkStky4q2qPFmrq9t751GZXIFwF3E7Nv_d8CKJJt46bdyk455dl3UM.JkWRWOxeWX2DoAtKo.PPg.chc8RGTFtu9UaByh1Vjd7zaF33Tf2vmic8rkXBZrKyGIGud8YY9kTP4ABWgE30QJFkzxeEh66CJnsjo6dFGOuJ5K11ygNjqoCZNMaK9_o4onZ.OjpAl0dqIdTJsZ_OFfWfM.s3IwuA9vAR2MwvxjbwawM.kU6joyGtbGMxaHX_pBAGqiM.UfWuYnEQC.GU.sCJHn44.2cwklo8znoVg.pRcuw8dYcqZmVztw06UP1daLrb79VJDq6FSK8HjAYPbmWtBhTcsNnoXQLPf2Ed1kYejhCZ8iwGTdAQ_v8ehDdXTLzAKxncT";
//    gzSize = 242;
    
//    int ret = gzDecompress(strAESDecrypt, gzSize, uncompressed, size_src*2);
//    printf("\ngzDecompress result: %d\n", ret);
//    for (; i<gzSize; ++i)
//    {
//        printf("%02x ", uncompressed[i]);
//    }
//    printf("uncompressed: %s\n", uncompressed);
//    printf("uncompressed size: %d\n", strlen(uncompressed));
//    
//    free(compressed);
//    free(uncompressed);
    return 0;
}
