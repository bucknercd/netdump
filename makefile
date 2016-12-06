CFLAGS= -g -Wall
all: logprt prtlog
logprt: logprt.o
prtlog: prtlog.o
logprt.o: logprt.c
prtlog.o: prtlog.c

clean:
	rm logprt.o logprt
	rm prtlog.o prtlog
tests:
	valgrind logprt logs/network.log
	valgrind prtlog logs/network.log
gdb:
	gdb prtlog logs/network.log
