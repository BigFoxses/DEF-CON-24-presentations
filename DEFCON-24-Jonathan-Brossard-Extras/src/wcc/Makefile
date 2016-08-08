CC := gcc
FILE := file
WCC := ./wcc
CFLAGS := -W -Wall -Wextra -fpie -pie -fPIC -g3 -ggdb -O0 -I../include

all::
	$(CC) $(CFLAGS) wcc.c -o wcc -lbfd
	cp wcc ../../bin/

test::
	$(WCC) /bin/ls -o ./ls.o -c
	$(CC) ls.o -o ./ls.so -shared -g3 -ggdb -O0
	$(FILE) ls.so
clean:
	rm -f wcc a.out wcc.o
