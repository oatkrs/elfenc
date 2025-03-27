/* elfenc.h */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <termios.h>
#include <bloatedutils.h>
#include "shellcode.h"
#include "crypto.h"

char prgawrapper(char*);

#define Hashsize 20
typedef unsigned char int8;
typedef unsigned short int int16;
typedef unsigned int int32;
typedef unsigned long long int int64;

typedef char Salt[4];
typedef unsigned char Hash[Hashsize];
typedef char Key[Hashsize];
typedef char Enc[358];

struct s_crypto {
    Salt salt;
    Hash hash;
    Key key;
    Enc state;
    int16 padding;
};
typedef struct s_crypto Crypto;

#define Align   0x00000004
#define Padding 0x10000
#define VBase   0x07000000
#define CodeSz  sizeof(Code)        /* 43 bytes */

#define ESize   sizeof(Elf32_Ehdr)
// #define HdrSz   (ESize + (sizeof(Elf32_Phdr) * 2) + sizeof(int32))
#define HdrSz   (ESize + (sizeof(Elf32_Phdr) * 2) + sizeof(int32))
#define Entry   (VBase+HdrSz)

#define $4 (int64 )
#define $2 (int32 )
#define $6 (int16 )
#define $8 (int8 *)
#define $c (char *)
#define $i (int)

struct s_elf {
    Elf32_Ehdr elf;
    Elf32_Phdr codehdr;
    Elf32_Phdr cipherhdr;
    int32 size;
    int8 codedata[CodeSz];
    int8 salt[4];
    int16 padding;
    int8 hashpadding[Padding];
    int8 cipherdata[];
};
typedef struct s_elf Elf;

static void hidehash(Hash,int8*,int16);
static Crypto *initcrypto(void);
static void encrypt(Crypto*,Elf*,int32);
static Elf *mkelf(int8,Crypto*);
static void savetofile(int32,Elf*);
int main(int,char**);
















