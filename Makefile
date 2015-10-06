BASE_DIR = .
SRC_DIR = $(BASE_DIR)/src
TEST_DIR = $(BASE_DIR)/test
MISC_DIR = $(BASE_DIR)/misc
SAMPLE_DIR= $(BASE_DIR)/sample

# CC = gcc
CFLAGS = -c -O0 -Wall -ggdb -Wextra
LDFLAGS = $(shell curl-config --libs) -ljansson

SYSTEMD_LDFLAGS = -lsystemd

default: gateway

gateway: journal-gateway-gelf

sample-gelf: json-gelf-encoding

sample-curl: curl-try-sending

journal-gateway-gelf: journal-gateway-gelf.o
	$(CC) journal-gateway-gelf.o $(LDFLAGS) $(SYSTEMD_LDFLAGS) -o journal-gateway-gelf

journal-gateway-gelf.o: $(SRC_DIR)/journal-gateway-gelf.c
	$(CC) $(CFLAGS) $(SRC_DIR)/journal-gateway-gelf.c -o journal-gateway-gelf.o

json-gelf-encoding: json-gelf-encoding.o
	$(CC) json-gelf-encoding.o -ljansson $(SYSTEMD_LDFLAGS) -o json-gelf-encoding

json-gelf-encoding.o: $(SAMPLE_DIR)/json-gelf-encoding.c
	$(CC) $(CFLAGS) $(SAMPLE_DIR)/json-gelf-encoding.c -o json-gelf-encoding.o

curl-try-sending: curl-try-sending.o
	$(CC) curl-try-sending.o $(shell curl-config --libs) -o curl-try-sending

curl-try-sending.o: $(SAMPLE_DIR)/curl-try-sending.c
	$(CC) $(CFLAGS) $(shell curl-config --cflags) $(SAMPLE_DIR)/curl-try-sending.c -o curl-try-sending.o

clean:
	rm -f *.o journal-gateway-gelf json-gelf-encoding curl-try-sending
