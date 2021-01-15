CC = gcc
VALGRIND=valgrind
DO_VALGRIND=
LDFLAGS =
CFLAGS = -Wall -Wextra -pedantic -g
OPENSSL_CFLAGS = $(shell pkg-config --cflags libcrypto)
OPENSSL_LIBS = $(shell pkg-config --libs libcrypto)

OBJS =	\
	mycms.o \
	$(NULL)

all:		\
		mycms \
		$(NULL)

clean:
	rm -f mycms $(OBJS)

check:		all
	VALGRIND="${VALGRIND}" DO_VALGRIND="${DO_VALGRIND}" ./test.sh

mycms:		\
		mycms.o \
		$(NULL)
	$(CC) -o $@ $(OBJS) $(OPENSSL_LIBS) $(LDFLAGS)

mycms.o:	\
		mycms.c \
		$(NULL)
	$(CC) -c -o $@ $(OPENSSL_CFLAGS) $(CFLAGS) mycms.c
