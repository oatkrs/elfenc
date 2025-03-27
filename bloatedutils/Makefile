flags=-O3 -Wall -std=c2x -I.
ldflags=-fPIC -shared -ldl -D_GNU_SOURCE
libdir=/lib//i386-linux-gnu
incdir=/usr/include

all: clean bloatedutils.so

install: bloatedutils.so
	cp bloatedutils.so $(libdir)/libbu.so
	cp bloatedutils.h  $(incdir)
	ldconfig

bloatedutils.so: bloatedutils.o
	cc ${flags} $^ -o $@ ${ldflags}

bloatedutils.o: bloatedutils.c
	cc ${flags} -c $^ $(ldflags)

clean:
	rm -f bloatedutils.o bloatedutils.so
