/* C language wrapper for arcfour.asm and hash.asm */
#include "crypto.h"

void ksa(char*,char*);
void prgainit(char*);
char prga(char*);
void whitewash(char*);
bool hash(char*,char*,char*,int);
unsigned char *kdf(char*,char*,int);

void ksawrapper(char*,char*);
void piwrapper(char*);
char prgawrapper(char*);
void wwwrapper(char*);
bool hashwrapper(char*,char*,char*,int);
unsigned char *kdfwrapper(char*,char*,int);

void ksawrapper(char *state, char *key) {
    volatile char padding[32];

    (void)padding;
    ksa(state, key);
    __asm("pop %eax");
    __asm("pop %eax");

    return;
}

void piwrapper(char *state) {
    volatile char padding[32];

    (void)padding;
    prgainit(state);
    __asm("pop %eax");

    return;
}

char prgawrapper(char *state) {
    volatile char padding[32];
    char ret;

    (void)padding;
    ret = prga(state);
    __asm("pop %eax");

    return ret;
}

void wwwrapper(char *state) {
    volatile char padding[32];

    (void)padding;
    (volatile void)whitewash(state);
    __asm("pop %eax");

    return;
}

bool hashwrapper(char *mem, char *msg, char *salt, int size) {
    bool ret;
    volatile char padding[32];

    (void)padding;
    ret = hash(mem, msg, salt, size);
    __asm("pop %eax");
    __asm("pop %eax");
    __asm("pop %eax");
    __asm("pop %eax");

    return ret;
}

unsigned char *kdfwrapper(char *passwd, char *salt, int size) {
    unsigned char *ret;
    volatile char padding[32];

    (void)padding;
    ret = kdf(passwd, salt, size);
    __asm("pop %eax");
    __asm("pop %eax");
    __asm("pop %eax");

    return ret;
}

void init(char *state, char *key) {
    memset(state, 0, 258);
    ksawrapper(state, key);
    piwrapper(state);
    (volatile void)wwwrapper(state);

    return;
}

char encc(char *state, const char c) {
    char ret, rc4byte;

    rc4byte = prgawrapper(state);
    ret = rc4byte ^ c;

    return ret;
}

void encs(char *state, char *str, int size) {
    char *p;
    char c;
    int n;

    for (p=str, n=size; n; n--, p++) {
        c = encc(state, *p);
        *p = c;
    }

    return;
}

unsigned char *mkhash(char *msg, char *salt) {
    unsigned char *p;
    unsigned short int size;
    bool ret;

    assert(strlen(salt) == 3);
    size = (Hashlen + 1);
    p = (unsigned char *)malloc((int)size);
    assert(p);

    memset(p, 0, size);
    size = (unsigned short int)strlen(msg);
    assert(size);

    ret = hashwrapper((char *)p, msg, salt, size);
    if (!ret) {
        free(p);
        return (unsigned char *)0;
    }
    
    return p;
}

unsigned char *mkkey(char *passwd, char *salt) {
    unsigned char *ret;
    unsigned short int size;

    assert(strlen(salt) == 3);
    size = (unsigned short int)strlen(passwd);

    assert(size);
    ret = kdfwrapper(passwd, salt, size);

    return ret;
}

unsigned int gensalt() {
    unsigned int ret;
    unsigned short int ab;
    unsigned char c;
    
    ab  = (unsigned short int)(getpid() & 0xffff);
    c   = (unsigned char)(time(0) % 256);
    ret = ((unsigned int)(c << 16) | ab);

    return ret;

}

unsigned short int csprng() {
    unsigned char buf[2];
    unsigned short int ret;
    unsigned short int *p;
    int n;

    memset(buf, 0, 2);
    n = getrandom(&buf, 2, GRND_RANDOM|GRND_NONBLOCK);

    switch (n) {
        case -1:
            if (errno == EAGAIN)
            {
                fprintf(stderr, "%s\n",
                    "ERROR: Not enough entropy for the CS-PRNG,"
                    " try again in a few minutes.");
                exit(-1);
            }
            else
                assert_perror(errno);
            break;

        case 2:
            // happy path
            break;

        default:
            fprintf(stderr, "%s\n",
                "ERROR: unknown error with the CS-PRNG");
            exit(-2);
            break;
    }

    p = (unsigned short int *)buf;
    ret = *p;

    return ret;
}