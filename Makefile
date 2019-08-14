CC=gcc
CFLAGS=-ggdb -Wall -Wextra -fstack-protector-all -flto -fPIE\
       `pkg-config --cflags --libs ncurses` -lpthread -lgcrypt -lgdbm
.PHONY: all clean
all: main
main: client.o main.o receiver.o util.o
	${CC} ${CFLAGS} $^ -o $@

%.o: %.c
	${CC} ${CFLAGS} -c $^ -o $@
clean:
	rm -f *.o main
