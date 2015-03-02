/* This tests whether you can write via systemd-journal-remote */
#include <stdio.h>
#include <string.h>
#include <alloca.h>
#include <assert.h>
#include <time.h>
#include <systemd/sd-journal.h>
#include <systemd/sd-id128.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>

#include "zmq-journal-gatewayd.h"

int main (int argc, char *argv[]){
	FILE *sjr;
	sjr = popen("/lib/systemd/systemd-journal-remote -o ~/minisample/logs/example.journal -", "w");
	assert(sjr);
	int fd = fileno(sjr);
	char msg[128];
	sprintf(msg, "MESSAGE=message from minisample at %i\nTEST_TYPE=systemd-journal-remote-test\n\n", time(NULL));
	fprintf(stderr, msg);
	write(fd, msg, strlen(msg));
	fflush(sjr);
	pclose(sjr);
	return 0;
}
