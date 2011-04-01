
CFLAGS  = -g -O0 --std=gnu99 -D_GNU_SOURCE -Wall -Werror -pedantic
LDFLAGS =

all: swatpd test

swatpd: swatpd.o
swatpd.o: src/swatpd.c

test: test.o
test.o: src/test.c

clean:
	rm -f *.o swatpd test

install:
	install -c -m 755 swatpd /usr/local/bin

%: %.o       ; gcc $(CFLAGS) -o $@ $^ $(LDFLAGS)
%.o: src/%.c ; gcc $(CFLAGS) -o $@ -c $^
