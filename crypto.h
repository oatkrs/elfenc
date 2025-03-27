/* crypto wrapper api */
#pragma once
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>
#include <time.h>
#include <sys/random.h>
#include <errno.h>
#define Hashlen 20

void init(char*,char*);
char encc(char*,const char);
void encs(char*,char*,int);

unsigned char *mkhash(char*,char*);
unsigned char *mkkey(char*,char*);
unsigned int gensalt(void);
unsigned short int csprng(void);