
CC=cc
CFLAGS=-g -O2 -pipe -Wall -DPASSWD -Werror-implicit-function-declaration

all: login_collab

clean:
	rm *.o

login.o: login.c
	$(CC) $(CFLAGS) -c login.c

login_collab.o: login_collab.c
	$(CC) $(CFLAGS) -c login_collab.c

pwd_gensalt.o: pwd_gensalt.c
	$(CC) $(CFLAGS) -c pwd_gensalt.c

login_collab: login.o login_collab.o pwd_gensalt.o
	$(CC) -lutil -o login_collab login.o login_collab.o pwd_gensalt.o
