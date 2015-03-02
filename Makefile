BASE_DIR = .
SRC_DIR = $(BASE_DIR)/src
MISC_DIR = $(BASE_DIR)/misc

# CC = gcc
CFLAGS = -c -O2 -Wall # -ggdb -Wextra
LDFLAGS = -lzmq -lczmq -ljansson

SYSTEMD_LDFLAGS = -lsystemd

default: zmq-journal-gatewayd zmq-journal-gatewayd-sink

gateway: zmq-journal-gatewayd
client: zmq-journal-gatewayd-sink

zmq-journal-gatewayd: zmq-journal-gatewayd.o
	$(CC) zmq-journal-gatewayd.o $(LDFLAGS) $(SYSTEMD_LDFLAGS) -o zmq-journal-gatewayd

zmq-journal-gatewayd.o: $(SRC_DIR)/zmq-journal-gatewayd.c
	$(CC) $(CFLAGS) $(SRC_DIR)/zmq-journal-gatewayd.c -o zmq-journal-gatewayd.o

zmq-journal-gatewayd-sink: zmq-journal-gatewayd-sink.o
	$(CC) zmq-journal-gatewayd-sink.o $(LDFLAGS) $(SYSTEMD_LDFLAGS) -o zmq-journal-gatewayd-sink

zmq-journal-gatewayd-sink.o: $(SRC_DIR)/zmq-journal-gatewayd-sink.c
	$(CC) $(CFLAGS) $(SRC_DIR)/zmq-journal-gatewayd-sink.c -o zmq-journal-gatewayd-sink.o

clean:
	rm -f *.o zmq-journal-gatewayd zmq-journal-gatewayd-sink

