ALG Support for NGINX
=====================

## Introducation

    ALG - Application Layer Gateway, is used to handle the protocol with dynamic port,
    which negotiated after control link established, like FTP, OPC DA, SIP, etc. This
    project provide NGINX the ability to proxy these protocols at 'stream' level(L4).

## Build

    $./configure --with-stream --with-stream_alg
    $make
    $make install

## How To Use

    modify 'nginx.conf', here is a simple demonstration:
    stream {
        upstream vsftpd {
            server 0.0.0.0:21;
        }
        server {
            listen 2121;
            proxy_timeout 65535;
            proxy_pass vsftpd;
            alg ftp;
        }
    }
    corresponding network topology is shown bellow:
    -----------------------------------------
    |client -> |NGINX Proxy Server -> server|
    |1.1.1.10  | 1.1.1.1:2121    1.1.1.1:21 |
    -----------------------------------------

## Ready Features

    a. FTP PASV/PORT mode support.
    b. OPC DA support.

## TO DO features

    a. User defined data link port range.
    b. packet filter by configuration.