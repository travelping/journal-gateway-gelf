BASE_DIR = .
SRC_DIR = $(BASE_DIR)/src
MISC_DIR = $(BASE_DIR)/misc
DESTDIR = /usr/bin

# CC = gcc
CFLAGS = -c -O2 -Wall # -ggdb -Wextra
LDFLAGS = -lzmq -lczmq -ljansson

SYSTEMD_FLAGS = -lsystemd-id128
SYSTEMD_FLAGS += -lsystemd

default: zmq-journal-gatewayd zmq-journal-gatewayd-sink

install: install_gateway install_client

gateway: zmq-journal-gatewayd
client: zmq-journal-gatewayd-sink

zmq-journal-gatewayd: zmq-journal-gatewayd.o
	$(CC) $(LDFLAGS) $(SYSTEMD_FLAGS) zmq-journal-gatewayd.o -o zmq-journal-gatewayd 

zmq-journal-gatewayd.o: $(SRC_DIR)/zmq-journal-gatewayd.c
	$(CC) $(CFLAGS) $(SRC_DIR)/zmq-journal-gatewayd.c -o zmq-journal-gatewayd.o

zmq-journal-gatewayd-sink: zmq-journal-gatewayd-sink.o
	$(CC) $(LDFLAGS) zmq-journal-gatewayd-sink.o -o zmq-journal-gatewayd-sink 

zmq-journal-gatewayd-sink.o: $(SRC_DIR)/zmq-journal-gatewayd-sink.c
	$(CC) $(CFLAGS) $(SRC_DIR)/zmq-journal-gatewayd-sink.c -o zmq-journal-gatewayd-sink.o

install_gateway:
	install -D zmq-journal-gatewayd $(DESTDIR)

install_client:
	install -D zmq-journal-gatewayd-sink $(DESTDIR)

clean:
	rm *.o zmq-journal-gatewayd zmq-journal-gatewayd-sink

