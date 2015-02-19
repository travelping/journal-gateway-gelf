BASE_DIR = $(shell cd .. && pwd -P)
SRC_DIR = $(BASE_DIR)/src
MISC_DIR = $(BASE_DIR)/misc
SYSTEMD_VERSION = $(shell systemctl --version | grep systemd | cut -d " " -f 2)
SYSTEMD_TEST = $(shell [ $(SYSTEMD_VERSION) -lt 209 ] && echo true)
DESTDIR = /usr/bin
SERVICE_DIR = /etc/systemd/system

CC = gcc
CFLAGS = -c -O2 #-Wall -Wextra  
LDFLAGS = -L/usr/local/lib -lzmq -lczmq -ljansson 
SYSTEMD_FLAGS = -lsystemd-id128

# libsystemd-journal got merged into libsystemd with version 209
ifeq ($(SYSTEMD_TEST), true)
	SYSTEMD_FLAGS += -lsystemd-journal
else
	SYSTEMD_FLAGS += -lsystemd
endif

# gateway and client can be build and installed separately
all: zmq-journal-gatewayd zmq-journal-gatewayd-client

install: install_gateway install_client


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

install_gateway:
	mkdir -p $(DESTDIR); cp zmq-journal-gatewayd $(DESTDIR)/
	cp $(MISC_DIR)/zmq-journal-gatewayd.service $(SERVICE_DIR)/

install_client:
	mkdir -p $(DESTDIR); cp zmq-journal-gatewayd-client $(DESTDIR)/
	cp $(MISC_DIR)/zmq-journal-gatewayd.service $(SERVICE_DIR)/

clean:
	rm *.o zmq-journal-gatewayd zmq-journal-gatewayd-client

