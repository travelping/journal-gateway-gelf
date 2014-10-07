BASE_DIR = $(shell cd .. && pwd -P)
SRC_DIR = $(BASE_DIR)/src
MISC_DIR = $(BASE_DIR)/misc
SYSTEMD_VERSION = $(shell systemctl --version | grep systemd | cut -d " " -f 2)
SYSTEMD_TEST = $(shell [ $(SYSTEMD_VERSION) -lt 212 ] && echo true)

CC = gcc
CFLAGS = -c -O2 #-Wall -Wextra  
LDFLAGS = -L/usr/local/lib -lzmq -lczmq -ljansson 
SYSTEMD_FLAGS = -lsystemd-id128

ifeq ($(SYSTEMD_TEST), true)
	SYSTEMD_FLAGS += -lsystemd-journal
else
	SYSTEMD_FLAGS += -lsystemd
endif

all: zmq-journal-gatewayd zmq-journal-gatewayd-client

gateway: zmq-journal-gatewayd

client: zmq-journal-gatewayd-client

zmq-journal-gatewayd: zmq-journal-gatewayd.o
	$(CC) $(LDFLAGS) $(SYSTEMD_FLAGS) zmq-journal-gatewayd.o -o zmq-journal-gatewayd 

zmq-journal-gatewayd.o: $(SRC_DIR)/zmq-journal-gatewayd.c
	$(CC) $(CFLAGS) $(SRC_DIR)/zmq-journal-gatewayd.c -o zmq-journal-gatewayd.o

zmq-journal-gatewayd-client: zmq-journal-gatewayd-client.o
	$(CC) $(LDFLAGS) zmq-journal-gatewayd-client.o -o zmq-journal-gatewayd-client 

zmq-journal-gatewayd-client.o: $(SRC_DIR)/zmq-journal-gatewayd-client.c
	$(CC) $(CFLAGS) $(SRC_DIR)/zmq-journal-gatewayd-client.c -o zmq-journal-gatewayd-client.o

clean:
	rm *.o zmq-journal-gatewayd zmq-journal-gatewayd-client

