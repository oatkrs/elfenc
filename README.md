# ELFEnc
### brainstorming for a better name in progress

When you do not want to share your source but want people to be able to use your program/logic, you simply obfuscate and compile your program, but when you dont want EVERYONE to be able to do that, you use ELFEnc, the only way to generate uncrackable static executables.

ELFEnc aims to secure any and every elf binary executable in existence to an uncrackable (as of today's technology) state.
Everything is done in memory with no static traces on the disk, so with a good password, you're theoretically safeguarding your executable forever

### Running

`Encrypting` an executable to form a new one

```elfenc /path_to_target_program outputfilename```

Setting up correct permissions for new executable

```bash$ chmod 755 outputfilename```

Elfenc generates a static-linked 32bit executable, that, in theory should run on any system.

---

# Dependencies

* gcc  >= 14.2.0
    - might require build from scratch
    - explicit support for the c23 C standard required (via gnu23 works as well)
* nasm >= 2.16.01
* bloatedutils >= 1.0
    - C utilitiy library that I'm working on for most of my future projects
* 32bit Linux operating system
    - I recommend i368 Debian bookworm for easy builds
    - the hardware cpu can be 64bit that's not an issue


### Security concerns

The hash, key derivation function and the stream cipher are all well-known already but in this implmentation are modified for increased security.
Any vulnerabilities related to RC4 are not carried over to this implementation due to everything being XOR'd over in the memory and having no relation to TLS, hence bypassing any RFC 7465 related concerns.

---

## Troubleshooting

### If it segfaults for the first password declaration

You either tweaked the Makefile to use c2x standard instead of c23 and thought "what could go wrong" (you sly fox) or you need to recompile GNU GCC, see below for further explaination and detailed instructions on how to do exactly that.

### "bad password" but I'm using the right password

You're typing wrong, OR the memory alignment is wrong, to fix it modify the "nalign" constant inside elfenc.asm, recompile elfenc then try running now. 
You might need to experiment aruond with values for distinct input binaries and/or for same identical/same binaries but dissimilar passwords, this is a work in progress after all :/

---

## Recommended build instructions

### Tested OS
debian i386-linux-gnu
https://cdimage.debian.org/debian-cd/current/i386/iso-cd/debian-12.10.0-i386-netinst.iso
 

### How to build gcc to actually get c23 working + nasm install for assembly

1. Installs outdated gcc and other requirements

```sudo apt install build-essential```

2. More requisites

```sudo apt-get install libgmp-dev libmpfr-dev libmpc-dev libisl-dev libzstd-dev -y```

> Note: Configuration (step 6) might take anywhere from a few minutes to few hours depending on the resources you've allocated to the VM, if it takes too long, you may download my preconfigured files ready for make, `unzip` and `cd` into folder and skip to Step 7.

3. Download latest/compatible GNU GCC

```wget http://ftp.gnu.org/gnu/gcc/gcc-14.2.0/gcc-14.2.0.tar.gz```

4. Unzip

```tar -xf gcc-14.2.0.tar.gz```

5. CD into unzipped folder

```cd gcc-14.2.0```

6. Configure the build for our platform

```./configure -v --build=i386-linux-gnu --host=i386-linux-gnu --target=i386-linux-gnu --prefix=/usr/local/gcc-14.2.0 --enable-checking=release --enable-languages=c,c++ --disable-multilib --program-suffix=-14.2.0```

7. Install GNU GCC

```sudo make install```

8. Changing the defaults

```sudo update-alternatives --install /usr/bin/g++ g++ /usr/local/gcc-14.1.0/bin/g++-14.2.0 14```

```sudo update-alternatives --install /usr/bin/gcc gcc /usr/local/gcc-14.1.0/bin/gcc-14.2.0 14```


9. Installing NASM
```sudo apt install nasm```

10. Getting the repo

```cd ~/```

```git clone https://github.com/oatkrs/elfenc.git```

```cd elfenc```

11. Install the library
You might have to tweak the Makefile to correct the directory, simply `ldd /bin/ls` and find what's the immediate parent directory for libc or libpcre, for this specific VM it was `i386-linux-gnu` , hence the libdir var is set to what it is right now.

```cd bloatedutils```

```make```

```sudo make install```

```cd ..```

Also, there are several other options like clean, all, and other file specifc ones, when recompiling it's always recommended to do `make clean`

12. Compiling ELFEnc

```make```

> This should compile with a few warnings and that is OK.
> output should be an extensionless linux executable named `elfenc` , and you're ready to run it

