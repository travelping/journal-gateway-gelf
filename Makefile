BASE_DIR = .
SRC_DIR = $(BASE_DIR)/src
TEST_DIR = $(BASE_DIR)/test
MISC_DIR = $(BASE_DIR)/misc
SAMPLE_DIR= $(BASE_DIR)/sample

CC = gcc
CFLAGS = -c -O0 -Wall -ggdb -Wextra
LDFLAGS = $(shell curl-config --libs) -ljansson

SYSTEMD_LDFLAGS = -lsystemd

default: journal-gateway-gelf-source

source: journal-gateway-gelf-source

sample-gelf: json-gelf-packaging

sample-curl: curl-try-sending

journal-gateway-gelf-source: journal-gateway-gelf-source.o
	$(CC) journal-gateway-gelf-source.o $(LDFLAGS) $(SYSTEMD_LDFLAGS) -o journal-gateway-gelf-source

journal-gateway-gelf-source.o: $(SRC_DIR)/journal-gateway-gelf-source.c
	$(CC) $(CFLAGS) $(SRC_DIR)/journal-gateway-gelf-source.c -o journal-gateway-gelf-source.o

json-gelf-packaging: json-gelf-packaging.o
	$(CC) json-gelf-packaging.o -ljansson $(SYSTEMD_LDFLAGS) -o json-gelf-packaging

json-gelf-packaging.o: $(SAMPLE_DIR)/json-gelf-packaging.c
	$(CC) $(CFLAGS) $(SAMPLE_DIR)/json-gelf-packaging.c -o json-gelf-packaging.o

curl-try-sending: curl-try-sending.o
	$(CC) curl-try-sending.o $(shell curl-config --libs) -o curl-try-sending

curl-try-sending.o: $(SAMPLE_DIR)/curl-try-sending.c
	$(CC) $(CFLAGS) $(shell curl-config --cflags) $(SAMPLE_DIR)/curl-try-sending.c -o curl-try-sending.o

clean:
	rm -f *.o journal-gateway-gelf-source json-gelf-packaging curl-try-sending
