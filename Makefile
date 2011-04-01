
all: swatpd test

swatpd: src/swatpd.c
	gcc -g -O0 --std=gnu99 -o swatpd src/swatpd.c

test: src/test.c
	gcc -g -O0 --std=gnu99 -o test src/test.c
