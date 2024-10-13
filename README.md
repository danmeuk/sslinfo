# sslinfo

SSL Information Tool

This tool will connect to an IP and port and report back details from the SSL/TLS negotiation.
You can specify types of STARTTLS to check ports that upgrade their security from insecure to secure.

For web ports, it will also report back some HTTP headers.

Currently, this has a static build system designed to build on FreeBSD 13/14 with OpenSSL installed as a port/package.
You will likely need to edit Makefile to tailor the build to your system.
