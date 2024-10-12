# $Id: Makefile 1061 2023-11-27 16:04:19Z dan $

sslinfo:	sslinfo.c ocsp_lcl.h
		clang -Wall -Werror -pedantic -I/usr/local/include -L/usr/local/lib -lssl -lcrypto -O2 -o sslinfo sslinfo.c
		# build static
		clang -std=c99 -D_THREAD_SAFE -D_REENTRANT -static -g -O2 -pedantic -Wall -Werror -pedantic -I/usr/include -I/usr/local/include -L/usr/local/lib -L /lib -L/usr/lib \
		-pthread -o sslinfo-static sslinfo.c \
		/usr/local/lib/libssl.a \
		/usr/local/lib/libcrypto.a

all:		sslinfo

clean:
		rm sslinfo sslinfo-static

install:	sslinfo
		install -b -d -o root -g wheel -m 0755 /usr/local/tools
		install -b -o root -g wheel -m 0755 -s sslinfo sslinfo-static /usr/local/tools/

