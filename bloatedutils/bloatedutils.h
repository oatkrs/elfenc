/* bloatedutils.h */
#pragma once
#pragma GCC diagnostic ignored "-Wstringop-truncation"
#pragma GCC diagnostic ignored "-Wformat-truncation="
#pragma GCC diagnostic push

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef unsigned char int8;
typedef unsigned short int int16;
typedef unsigned int int32;

/* C */
void copy(int8*,int8*,int16);

/* N */
int16 nstoh(int16);

/* P */
void printhex(int8*,int16,int8);

/* T */
int8 *todotted(in_addr_t);

/* Z */
void zero(int8*,int16);