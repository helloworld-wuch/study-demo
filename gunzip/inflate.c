#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define CHUNK 50000

/**
    z_stream结构
    z_const Bytef *next_in; 指向需要压缩或解压的数据的指针
    uInt     avail_in;      可用于压缩或解压缩的输入数据字节长度
    uLong    total_in;      已经压缩或解压缩的输入数据字节长度
    Bytef    *next_out;     指向输出数据的指针
    uInt     avail_out;     可用于存储压缩或解压缩的输出数据字节长度
    uLong    total_out;     已经压缩或解压缩的输出数据字节长度
    z_const char *msg;      zlib 库返回的错误信息
    struct internal_state FAR *state; zlib 库内部使用的状态信息，不需要应用程序进行修改

    alloc_func zalloc;      用于内存分配的函数指针，一般使用 malloc
    free_func  zfree;       用于内存释放的函数指针，一般使用 free
    voidpf     opaque;      用于内存分配和释放的自定义参数，一般设为 NULL。
    int     data_type;      输入数据的类型。取值为 Z_ASCII / Z_BINARY / Z_UNKNOWN
    uLong   adler;          Adler-32 校验和，可以用来校验压缩前后数据的一致性
    uLong   reserved;   ·   保留字段，目前未被使用
**/


//一次性读取文件数据(最大CHUNK个字节)，并对数据进行压缩
int main(int argc, char **argv) {
    int ret;
    z_stream strm_de, strm_in;
    char in[CHUNK];
    char out[CHUNK];
    FILE *src, *dst;
    int windowBits = 15;
    int GZIP_ENCODING = 16;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <src_file> <dst_file>\n", argv[0]);
        exit(1);
    }

    // 打开源文件和目标文件
    src = fopen(argv[1], "rb");
    if (src == NULL) {
        fprintf(stderr, "Can't open file %s for reading\n", argv[1]);
        exit(1);
    }

    dst = fopen(argv[1], "rb");
    if (src == NULL) {
        fprintf(stderr, "Can't open file %s for reading\n", argv[2]);
        exit(1);
    }

    // 初始化压缩流
    memset(&strm_de, 0, sizeof(strm_de));
    strm_de.zalloc = Z_NULL;
    strm_de.zfree  = Z_NULL;
    strm_de.opaque = Z_NULL;

/**
*** deflate（压缩）操作的初始化
*** 1、deflateInit2()即对strm_de类型的变量的初始化
*** 2、Z_DEFAULT_COMPRESSION指定默认的压缩级别
*** 3、windowBits|GZIP_ENCODING设置gzip压缩格式，windowBits指定压缩窗口的大小，GZIP_ENCODING指定压缩格式为gzip格式
*** 4、8指定压缩数据块的大小，也称为压缩级别
*** 5、Z_DEFAULT_STRATEGY指定压缩策略
**/
    if (deflateInit2(&strm_de, Z_DEFAULT_COMPRESSION, Z_DEFLATED, windowBits|GZIP_ENCODING, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        fprintf(stderr, "Error: failed to initialize zlib deflate stream\n");
        exit(1);
    }

    // 读取源文件并压缩数据
    do {
        strm_de.avail_in = fread(in, 1, CHUNK, src);
        if (ferror(src)) {
            (void)deflateEnd(&strm_de);
            fprintf(stderr, "Error: failed to read src file\n");
            exit(1);
        }

        if (strm_de.avail_in == 0) break;
        strm_de.next_in = (unsigned char *)in;

        do {
            strm_de.avail_out = CHUNK;
            strm_de.next_out = (unsigned char *)out;
            ret = deflate(&strm_de, Z_FINISH);
            if (ret == Z_STREAM_ERROR) {
                (void)deflateEnd(&strm_de);
                fprintf(stderr, "Error: zlib deflate failed\n");
                exit(1);
            }
        } while (strm_de.avail_out == 0);

    } while (ret != Z_STREAM_END);

    // 初始化压缩流
    memset(&strm_in, 0, sizeof(strm_in));
    memset(&in, 0, sizeof(CHUNK));
    strm_in.zalloc = Z_NULL;
    strm_in.zfree  = Z_NULL;
    strm_in.opaque = Z_NULL;

    if (inflateInit2(&strm_in, MAX_WBITS + 16) != Z_OK) {
        fprintf(stderr, "Error: failed to initialize zlib inflate stream\n");
        exit(1);
    }

    // 解压数据
    strm_in.avail_in = strm_de.total_out;
    if (strm_in.avail_in == 0) break;
    strm_in.next_in = (unsigned char *)out;

    do {
        strm_in.avail_out = CHUNK;
        strm_in.next_out = (unsigned char *)in;
        ret = inflate(&strm_in, Z_FINISH);
        if (ret == Z_STREAM_ERROR) {
            (void)inflateEnd(&strm_in);
            fprintf(stderr, "Error: zlib inflate failed\n");
            exit(1);
        }
    } while (strm_in.avail_out == 0);

    printf("len:%lu, data:%s\n", strm_in.total_out, in);        


    // 结束压缩流并关闭文件
    (void)deflateEnd(&strm_de);
    (void)inflateEnd(&strm_in);
    fclose(src);
    fclose(dst);

    return 0;
}
