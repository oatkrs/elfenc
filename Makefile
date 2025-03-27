asmopt = -O0
copt = -O0 -Wall -Wextra -std=c23
deps = 
ldflags = -lbu

.PHONY: all clean

all: clean elfenc

elfenc-asm: elfenc-asm.o util.o hash.o arcfour.o
	ld $^ -o $@

elfenc: tmp.bin elfenc-c.o crypto.o hash.o arcfour.o util.o
	cc $(copt) $(^:tmp.bin=) $(deps) -o $@ $(ldflags)

tmp.bin: elfenc.asm util.asm util.asmh hash.asm arcfour.asm gensc
	rm -f tmp.bin tmp.asm
	chmod 755 ./mkbuild.sh
	./mkbuild.sh
	nasm -f bin tmp.asm -o tmp.bin
	rm -f shellcode.h
	./gensc ./tmp.bin > shellcode.h

gensc: gensc.o
	cc $(copt) $^ $(deps) -o $@ $(ldflags)

gensc.o: gensc.c
	cc $(copt) -c $< -o $@

arcfour.o: arcfour.asm util.asmh
	nasm -f elf $< -o $@

crypto.o: crypto.c crypto.h
	cc $(copt) -c $< -o $@

hash.o: hash.asm util.asmh
	nasm -f elf $< -o $@

util.o: util.asm util.asmh
	nasm -f elf $< -o $@

elfenc-asm.o: elfenc.asm
	nasm -f elf $(asmopt) $< -o $@

elfenc-c.o: elfenc.c
	cc $(copt) -c $< -o $@

clean:
	rm -f elfenc gensc shellcode.h tmp.bin tmp.asm *.o
