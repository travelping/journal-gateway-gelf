
all: zmq-journal-gatewayd zmq-journal-gatewayd-client clean 

zmq-journal-gatewayd: zmq-journal-gatewayd.o
	gcc zmq-journal-gatewayd.o -o zmq-journal-gatewayd -lzmq -lczmq

zmq-journal-gatewayd.o: zmq-journal-gatewayd.c
	gcc -c zmq-journal-gatewayd.c -o zmq-journal-gatewayd.o

zmq-journal-gatewayd-client: zmq-journal-gatewayd-client.o
	gcc zmq-journal-gatewayd-client.o -o zmq-journal-gatewayd-client -lzmq -lczmq

zmq-journal-gatewayd-client.o: zmq-journal-gatewayd-client.c
	gcc -c zmq-journal-gatewayd-client.c -o zmq-journal-gatewayd-client.o

clean:
	rm *.o

