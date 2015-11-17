
CC=cc
CFLAGS=-g -O2 -pipe -Wall -Werror-implicit-function-declaration

all: login_collab

install: all
	install -o root -g auth -m u=rxs,go=rx login_collab /usr/libexec/auth/login_-collab

clean:
	rm -f *.o login_collab

login.o: login.c
	$(CC) $(CFLAGS) -c login.c

login_collab.o: login_collab.c
	$(CC) $(CFLAGS) -c login_collab.c

login_collab: login.o login_collab.o
	$(CC) -lutil -o login_collab login.o login_collab.o
