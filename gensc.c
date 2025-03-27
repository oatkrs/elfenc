/* elfenc "shellcode" generator */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <bloatedutils.h>

#define $1 (int8*)
#define $2 (int16)
#define $4 (int32)
#define $8 (int64)
#define $c (char *)
#define $i (int)

#define zero(x) do { \
    *(x) = 0; \
    *((x)+1) = 0; \
} while(0)

typedef unsigned long long int int64;

void printcode(int16,int32);
int32 filesize(int16);
void usage(int8*);
int main(int,char**);

void printcode(int16 fd, int32 filesz) {
    signed int n;
    int32 i;
    int8 buf[2];

    i = 0;
    assert(fd > 0);

    printf("\t\"");
    do {
        zero(buf);
        n = read($i fd, $c buf, 1);
        if (n!=1) {
            printf("\"\n");
            break;
        }

        i++;
        printf("\\x%.02x", *buf);

        if (i >= filesz) {
            printf("\"\n");
            break;
        }
        else if (!(i%10))
           printf("%s", "\" \\\n\t\"");
        
        fflush(stdout);
    } while (true);

    return;
}

int32 filesize(int16 fd) {
    signed int Int;
    struct statx sx;
    int32 ret;

    assert(fd > 0);
    Int = statx($i fd, "", AT_EMPTY_PATH, STATX_SIZE, &sx);
    if (Int || !sx.stx_size)
        return 0;
    else
        ret = $4 sx.stx_size;
    
    return ret;
}

void usage(int8 *arg) {
    fprintf(stderr,
        "Usage: %s <file.bin>\n"
        "Note:\n"
        "\tThe file should contain all the machine code of\n"
        "\tsection .text, and no symbols and nothing else.\n",
            $c arg);

    return;
}

int main(int argc, char *argv[]) {
    signed int Int;
    int32 filesz;
    int16 fd;
    int8 *file;

    if (argc != 2) {
        usage($1 *argv);
        exit(-1);
    }

    file = $1 argv[1];
    Int = open($c file, O_RDONLY);
    if (Int < 1)
        assert_perror(errno);
    fd = $2 Int;

    filesz = filesize(fd);
    assert (filesz);

    printf("%s\n", "/* shellcode.h */");
    printf("%s\n", "#define Code \\");
    printcode(fd, filesz);
    fflush(stdout);
    close($i fd);

    return 0;
}