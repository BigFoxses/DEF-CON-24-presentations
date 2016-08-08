CC := gcc
CFLAGS := -W -Wall -Wextra -fpie -pie -fPIC -g3 -ggdb -O0 -I../include

all::
	$(CC) $(CFLAGS) wld.c -o wld -lbfd
	cp wld ../../bin/
test:

clean:
	rm -f wld a.out
