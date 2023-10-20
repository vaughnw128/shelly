all: libpamd.so

libpamd.so: libpamd.c
	gcc -Wall -fPIC -shared -o libpamd.so libpamd.c -ldl

.PHONY clean:
	rm -f libpamd.so
