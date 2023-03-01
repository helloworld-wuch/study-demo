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
    z_stream strm;
    char in[CHUNK];
    char out[CHUNK];
    FILE *source;
    int windowBits = 15;
    int GZIP_ENCODING = 16;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <source_file>\n", argv[0]);
        exit(1);
    }

    // 打开源文件和目标文件
    source = fopen(argv[1], "rb");
    if (source == NULL) {
        fprintf(stderr, "Can't open file %s for reading\n", argv[1]);
        exit(1);
    }

    // 初始化压缩流
    memset(&strm, 0, sizeof(strm));
    strm.zalloc = Z_NULL;
    strm.zfree  = Z_NULL;
    strm.opaque = Z_NULL;

/**
*** deflate（压缩）操作的初始化
*** 1、deflateInit2()即对strm类型的变量的初始化
*** 2、Z_DEFAULT_COMPRESSION指定默认的压缩级别
*** 3、windowBits|GZIP_ENCODING设置gzip压缩格式，windowBits指定压缩窗口的大小，GZIP_ENCODING指定压缩格式为gzip格式
*** 4、8指定压缩数据块的大小，也称为压缩级别
*** 5、Z_DEFAULT_STRATEGY指定压缩策略
**/
    if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, windowBits|GZIP_ENCODING, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        fprintf(stderr, "Error: failed to initialize zlib deflate stream\n");
        exit(1);
    }

    // 读取源文件并压缩数据
    do {
        strm.avail_in = fread(in, 1, CHUNK, source);
        if (ferror(source)) {
            (void)deflateEnd(&strm);
            fprintf(stderr, "Error: failed to read source file\n");
            exit(1);
        }

        if (strm.avail_in == 0) break;
        strm.next_in = (unsigned char *)in;

        do {
            strm.avail_out = CHUNK;
            strm.next_out = (unsigned char *)out;
            ret = deflate(&strm, Z_FINISH);
            if (ret == Z_STREAM_ERROR) {
                (void)deflateEnd(&strm);
                fprintf(stderr, "Error: zlib deflate failed\n");
                exit(1);
            }
        } while (strm.avail_out == 0);

    } while (ret != Z_STREAM_END);

    int i = 0;
    for (; i<strm.total_out; ++i)
    {
        printf("%02x ", out[i]);
    }
    printf("\ncompressed size: %lu\n", strm.total_out);


    // 结束压缩流并关闭文件
    (void)deflateEnd(&strm);
    fclose(source);

    return 0;
}
