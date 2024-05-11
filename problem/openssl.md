1、openssl version 报错"/lib64/libssl.so.1.1: version `OPENSSL_1_1_1' not found (required by openssl)"
    ①下载源码包：https://www.openssl.org/source/openssl-1.1.1a.tar.gz
    ②生成makefile  ./config shared --openssldir=/usr/local/openssl --prefix=/usr/local/openssl
    ③编译安装      make -j4 && make install
    ④echo "/usr/local/lib64/" >> /etc/ld.so.conf && ldconfig