/* elfenc.c */
#include "elfenc.h"

static void hidehash(Hash hash, int8 *mem, int16 depth) {
    int8 *c;
    int8 *p;
    signed int n;
    int16 rnd;
    int16 offset;

    assert(!(Padding % 2));
    for (n=(Padding-1), p=mem; (n>=1); p+=2, n-=2) {
        rnd = $6 csprng();
        c = (int8 *)&rnd;
        *p = *c;
        c++;
        *(p+1) = *c;
    }

    /* Im not entirely comfortable with this part */
    /*   but the alternative is too complicated */
    offset = (depth > (Padding-Hashsize)) ?
            (Padding-Hashsize) :
        depth;

    p = (mem + offset);
    memcpy(p, hash, Hashsize);

    return;
}

static Crypto *initcrypto() {
    Crypto *c;
    int16 size;
    int8 buf1[64], buf2[64];
    int8 *pw;
    int8 *(*f)(int8*,int8*);
    int32 salt;

    bool echo(bool on) {
        struct termios t;

        tcgetattr(0, &t);
        t.c_lflag = (on) ?
            t.c_lflag | ECHO :
        t.c_lflag & ~ECHO;
        tcsetattr(0, 0, &t);

        return on;
    }

    int8 *readkey(int8 *prompt, int8 *buf) {
        int8 *p;
        int8 size, idx;
        int8 *verify;
        bool passwords_match;

        fprintf(stderr, "%s ", prompt);
        fflush(stderr);

        echo(false);
        memset(buf, 0, 64);
        read(0, (char *)buf, 63);
        size = (int8)strlen((char *)buf);
        idx = size -1;
        p = (int8 *)buf + idx;

        *p = 0;
        echo(true);
 
        if (strcmp($c prompt, "Verify:")) {
            fprintf(stderr, "\n");
            fflush(stderr);

            verify = readkey($8 "Verify:", $8 &buf2);
            passwords_match = !((bool)strncmp($c buf, $c verify, 63));

            fprintf(stderr, "\n");
            fflush(stderr);

            assert(passwords_match);
        }

        return buf;
    }

    size = sizeof(struct s_crypto);
    c = (Crypto *)malloc(size);
    assert(c);
    zero($8 c, size);

    // salt = (int32)gensalt();
    // memcpy(c->salt, (char *)&salt, 3);
    // c->padding = $6 csprng();

    /* (xx) !!!! */
    salt = (int32)0x00aabbcc;
    memcpy(c->salt, (char *)&salt, 3);
    c->padding = 0x0014;

    fprintf(stderr,
        "Choose a secure password to be used as encryption key.\n");
    f  = &readkey;
    pw = f($8 "Password:", $8 &buf1);
    
    printf("%s", "Preparing all the crypto stuff (this might "
            "take a couple of minutes)...");
    fflush(stdout);

    memcpy(c->hash, mkhash($c pw, c->salt), sizeof(Hash));
    memcpy(c->key, mkkey($c pw, c->salt), sizeof(Key));
    init(c->state, c->key);
    printf("done\n");

    /* (xx) !!!
    printf ("%hhx %hhx %hhx %hhx %hhx\n",
        (int8)encc(c->state, 0),
        (int8)encc(c->state, 0),
        (int8)encc(c->state, 0),
        (int8)encc(c->state, 0),
        (int8)encc(c->state, 0)
    );
    fflush(stdout);
    exit(0);
    */

    return c;
}

static void encrypt(Crypto *c, Elf *e, int32 filesize) {
    int32 n;
    int8 *p;
    int8 ch;
    int32 i;
    unsigned char arc;

    i = 0;
    n = (sizeof(int16) + Padding + filesize);
    for (p=((int8 *)&e->padding); n; n--, p++) {
        // ch = (int8)encc(c->state, (char)*p);
        arc = prgawrapper(c->state);
        ch = (int8)(arc ^ *p);
        if (i<10)
            printf("0x%hhx xor 0x%hhx -> 0x%hhx\n",
                arc, (char)*p, (char)ch);
        *p = ch;
        i++;
    }

    return;
}

Elf *mkelf(int8 fd, Crypto *c) {
    struct statx sx;
    // int16 n;
    int i;
    // int8 *p;
    // int8 buf[1024];
    int32 size, length;
    Elf *elf;
    Elf e = {
        .elf = {
            .e_ident = {
                ELFMAG0,
                ELFMAG1,
                ELFMAG2,
                ELFMAG3,
                ELFCLASS32,
                ELFDATA2LSB,
                EV_CURRENT,
                ELFOSABI_SYSV,
                EI_ABIVERSION,
                EI_PAD,
                EI_NIDENT
            },
            .e_type = ET_EXEC,
            .e_machine = EM_386,
            .e_version = EV_CURRENT,
            .e_entry = Entry,
            .e_phoff = ESize,
            .e_shoff = 0,
            .e_flags = 0,
            .e_ehsize = ESize,
            .e_phentsize = sizeof(Elf32_Phdr),
            .e_phnum = 2,
            .e_shentsize = 0,
            .e_shnum = 0,
            .e_shstrndx = SHN_UNDEF
        },
        .codehdr = {
            .p_type = PT_LOAD,
            .p_offset = 0,
            // .p_offset = HdrSz,
            // .p_vaddr = (VBase+HdrSz),
            .p_vaddr = VBase,
            .p_paddr = 0,
            .p_filesz = CodeSz,
            .p_memsz = CodeSz,
            .p_flags =  PF_R
                        | PF_W
                        | PF_X,
            .p_align = Align
        },
        .cipherhdr = {
            .p_type = PT_LOAD,
            .p_offset = (HdrSz+CodeSz),
            .p_vaddr = (VBase+(HdrSz+CodeSz)),
            .p_paddr = 0,
            .p_filesz = 000,
            .p_memsz = 000,
            .p_flags =  PF_R
                        | PF_W
                        | PF_X,
            .p_align = Align
        },
        .size = $2 000,
        .codedata = {0},
        .salt = {0},
        .padding = 0,
        .hashpadding = {0}
   };

    printf("Generating elf...");
    fflush(stdout);

    memcpy(&e.salt, c->salt, sizeof(Salt));
    printf("ep:0x%.04hx\tcp:0x%.04hx\t", e.padding, c->padding);
    printf("csalt: %.02hhx %.02hhx %.02hhx %.02hhx\n",
        c->salt[0], c->salt[1], c->salt[2], c->salt[3]);
    printf("esalt: %.02hhx %.02hhx %.02hhx %.02hhx\n",
        e.salt[0], e.salt[1], e.salt[2], e.salt[3]);
    e.padding = c->padding;
    printf("ep:0x%.04hx\tcp:0x%.04hx...", e.padding, c->padding);
    fflush(stdout);

    i = statx($i fd, "", AT_EMPTY_PATH, STATX_SIZE, &sx);
    assert(!i);
    // n = 1023;
    assert(fd > 0);
    assert(sx.stx_size);
    size = sx.stx_size;
    length = (sizeof(struct s_elf) + size);
    elf = (Elf *)malloc($i length);
    assert(elf);
    zero($8 elf, $6 length);
    // zero(buf, 1024);
    printf("done\nInjecting shellcode...");
    fflush(stdout);
    memcpy($c e.codedata, $c Code, $i CodeSz);

    printf("done\nEncrypting...");
    fflush(stdout);
    hidehash(c->hash, e.hashpadding, c->padding);
    memcpy($c elf, $c &e, sizeof(struct s_elf));
    printf("elfsalt: %.02hhx %.02hhx %.02hhx %.02hhx\n",
        elf->salt[0], elf->salt[1], elf->salt[2], elf->salt[3]);
 
    /* (xx) */
    i = read($i fd, elf->cipherdata, size);
    assert($2 i == size);

/*
    while (n == 1023) {
        int32 z;

        n = $6 read($i fd, $c buf, 1023);
        if (!n)
            break;

        assert(n > 0);
        z = size;
        size += $2 n;
        length = (sizeof(struct s_elf) + size);
        elf = (Elf *)realloc((Elf *)elf, $i length);
        p = (elf->cipherdata +z);
        assert(elf);
        // zero(p, n);
        memcpy($c p, $c buf, $i n);
        // zero(buf, 1023);
    }
*/

    elf->cipherhdr.p_filesz =
        elf->cipherhdr.p_memsz =
        (size+sizeof(int32)+sizeof(int16)+Padding);
    length = (sizeof(struct s_elf) + size);
    elf->size = length;
    encrypt(c, elf, size);
    printf("done\n");
    
    return elf;
}

static void savetofile(int32 fd, Elf *elf) {
    /*
    int8 buf[2];
    int8 *p;
    int32 x;
    int16 n;
    */

    assert(fd > 0);
    assert(elf);

    /*
    for (n=1,x=elf->size,p=$8 elf; (x) && (n==1); x--,p++) {
        zero(buf, 2);
        *buf = *p;
        n = $6 write($i fd, $c buf, 1);
    }
    */
   write($i fd, $c elf, $i elf->size);

    return;
}

int main(int argc, char *argv[]) {
    int32 in, out;
    int8 *infile, *outfile;
    Crypto *c;
    Elf *elf;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s SOURCE DESTINATION\n",
            *argv);

        return -1;
    }

    infile = $8 argv[1];
    outfile = $8 argv[2];

    c = initcrypto();
    in  = $2 open($c infile, O_RDONLY);
    assert(in > 0);

    elf = mkelf(in, c);
    close(in);

    out = $2 open($c outfile, O_WRONLY|O_CREAT|O_TRUNC, 00755);
    assert(out > 0);
    // __asm("pop %edx");
    savetofile(out, elf);
    close(out);
    printf("Outfile '%s' successfully generated.\n", outfile);

    return 0;
}