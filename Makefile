CC=gcc
CFLAGS=-c -O2 #-Wall -Wextra  
LDFLAGS=-L/usr/local/lib -lzmq -lczmq -ljansson -lsystemd-journal -lsystemd-id128

all: zmq-journal-gatewayd zmq-journal-gatewayd-client clean 

zmq-journal-gatewayd: zmq-journal-gatewayd.o
	$(CC) $(LDFLAGS) zmq-journal-gatewayd.o -o zmq-journal-gatewayd 

zmq-journal-gatewayd.o: zmq-journal-gatewayd.c
	$(CC) $(CFLAGS) zmq-journal-gatewayd.c -o zmq-journal-gatewayd.o

zmq-journal-gatewayd-client: zmq-journal-gatewayd-client.o
	$(CC) $(LDFLAGS) zmq-journal-gatewayd-client.o -o zmq-journal-gatewayd-client 

zmq-journal-gatewayd-client.o: zmq-journal-gatewayd-client.c
	$(CC) $(CFLAGS) zmq-journal-gatewayd-client.c -o zmq-journal-gatewayd-client.o

clean:
	rm *.o

