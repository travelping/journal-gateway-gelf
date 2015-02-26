 /*
 * Copyright (c) 2013-2014 by Travelping GmbH <info@travelping.com>
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
*/

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <signal.h>

#include "zmq-journal-gatewayd.h"

static zctx_t *ctx;
static void *client;
uint64_t initial_time;
int log_counter = 0;
int heartbeating = HEARTBEATING; 

/* cli arguments */
int     reverse=0, at_most=-1, follow=0, listening=0;
char    *since_timestamp=NULL, *until_timestamp=NULL, *client_socket_address=NULL, *format=NULL,
        *since_cursor=NULL, *until_cursor=NULL, *filter=NULL;

char* make_json_timestamp(char *timestamp){
    if (timestamp == NULL) {
        return NULL;
	}

	if (0 == strcmp("now", timestamp)) {
		return "now";
	}

    char *json_timestamp = (char *) malloc(sizeof(char) * 21);
    json_timestamp[0] = '\0'; 
    char *ptr = strtok(timestamp, " ");
    strcat(json_timestamp, timestamp);
    strcat(json_timestamp, "T");
    ptr = strtok(NULL, " ");
    strcat(json_timestamp+11, timestamp+11);
    strcat(json_timestamp, "Z");
    return json_timestamp;
}

char *build_query_string(){
    json_t *query = json_object();
    if (reverse == 1) json_object_set_new(query, "reverse", json_true());
    if (at_most >= 0) json_object_set_new(query, "at_most", json_integer(at_most));
    if (follow == 1) json_object_set_new(query, "follow", json_true());
    if (listening == 1) json_object_set_new(query, "listen", json_true());
    if (format != NULL) json_object_set_new(query, "format", json_string(format));
    char* json_since = make_json_timestamp(since_timestamp);
    if (json_since != NULL) {
        json_object_set_new(query, "since_timestamp", json_string(json_since));
        free(json_since);
    }
    char* json_until = make_json_timestamp(until_timestamp);
    if (json_until != NULL) { 
        json_object_set_new(query, "until_timestamp", json_string(json_until));
        free(json_until);
    }
    if (since_cursor != NULL) json_object_set_new(query, "since_cursor", json_string(since_cursor));
    if (until_cursor != NULL) json_object_set_new(query, "until_cursor", json_string(until_cursor));
    if (filter != NULL){ 
        json_t *json_fiter = json_loads(filter, JSON_REJECT_DUPLICATES, NULL);
        json_object_set_new(query, "field_matches", json_fiter);
    }
    char* query_string = json_dumps(query, JSON_ENCODE_ANY);
    json_decref(query);
    return query_string;
}

/* for measuring performance of the gateway */
void benchmark(uint64_t initial_time, int log_counter) {
    uint64_t current_time = zclock_time ();
    uint64_t time_diff_sec = (current_time - initial_time)/1000;
    uint64_t log_rate_sec = log_counter / time_diff_sec;
    printf("<< sent %d logs in %d seconds ( %d logs/sec ) >>\n", log_counter, time_diff_sec, log_rate_sec);
}

static bool active = true;
void stop_handler(int dummy) {
    //printf("DBG: stop handler called\n");
    int rc;
    zmq_pollitem_t items [] = {
        { client, 0, ZMQ_POLLIN, 0 },
    };

    zstr_send (client, STOP);
    char *frame_string = NULL;
    do {
        rc = zmq_poll (items, 1, 1000 * ZMQ_POLL_MSEC);
        if ( rc == 0 ) break;
        else{
            if (frame_string != NULL) 
                free(frame_string);
            frame_string = zstr_recv(client);
            log_counter++;
        }
    }while( strcmp( frame_string, STOP ) != 0 );
    if (frame_string != NULL) 
        free(frame_string);

    /* can be used for benchmarking the client */
    //benchmark(initial_time, log_counter);

    /* stop the client */
    active = false;
}

/* Do sth with the received message */
int response_handler(zframe_t* cid, zmsg_t *response, FILE *sjr){
    fprintf(stderr, "DBG: in response_handler\n");
    zframe_t *frame;
    void *frame_data;
    size_t frame_size;
    int more;
    int ret = 0; 

    do{
        frame = zmsg_pop (response);
        frame_size = zframe_size(frame);
        more = zframe_more (frame);
        frame_data = zframe_data(frame);
        if( memcmp( frame_data, END, strlen(END) ) == 0 ){
            zframe_destroy (&frame);
            if (listening) {
                ret =  1;
            }
            break;
        }
        else if( memcmp( frame_data, ERROR, strlen(ERROR) ) == 0 ){
            zframe_destroy (&frame);
            fprintf(stderr, "DBG: received ERROR\n");
            ret = -1;
            break;
        }
        else if( memcmp( frame_data, HEARTBEAT, strlen(HEARTBEAT) ) == 0 ) NULL;
        else if( memcmp( frame_data, TIMEOUT, strlen(TIMEOUT) ) == 0 ) NULL;
        else if( memcmp( frame_data, READY, strlen(READY) ) == 0 ) NULL;
        else if( memcmp( frame_data, LOGON, strlen(LOGON) ) == 0 ){
            /* send query as first response */
            char *query_string = build_query_string();
			zmsg_t *m = zmsg_new(); assert(m);
			zframe_t *queryframe = zframe_new(query_string, strlen(query_string)+1);
			assert(queryframe);
			zmsg_push(m, queryframe);
			zmsg_push(m, cid);
			zmsg_send (&m, client);
            free(query_string);
        }
        else{
			assert(((char*)frame_data)[0] == '_');
            fprintf(stderr, "DBG: before atempt to write to journal\n" );
            int fd = fileno(sjr);

            fprintf(stderr, "writing %lu bytes to %i: %s\n---\n", frame_size, fd, frame_data);
			fflush(stderr);
            write(fd, frame_data, frame_size);

            write(fd, "\n", 1);
            fprintf(stderr, "DBG: after atempt to write to journal\n" );
            log_counter++;
        }
        fprintf(stderr, "DBG: destroying frame\n");
        zframe_destroy (&frame);
    }while(more);
    return ret;
}

int main ( int argc, char *argv[] ){

    struct option longopts[] = {
        { "reverse",        no_argument,            &reverse,     1   },
        { "at_most",        required_argument,      NULL,         'a' },
        { "since",          required_argument,      NULL,         'b' },
        { "until",          required_argument,      NULL,         'c' },
        { "since_cursor",   required_argument,      NULL,         'd' },
        { "until_cursor",   required_argument,      NULL,         'e' },
        { "format",         required_argument,      NULL,         'f' },
        { "follow",         no_argument,            NULL,         'g' },
        { "help",           no_argument,            NULL,         'h' },
        { "filter",         required_argument,      NULL,         'i' },
        { "socket",         required_argument,      NULL,         's' },
        { "listen",         no_argument,            NULL,         'j' },
        { 0, 0, 0, 0 }
    };

    int c;

    /*set default since filter*/
    //since_timestamp = "now";
    //needs correct formatting, source does not accept token "now"

    while((c = getopt_long(argc, argv, "a:b:c:d:e:f:ghs:", longopts, NULL)) != -1) {
        switch (c) {
            case 'a':
                at_most = atoi(optarg);
                break;
            case 'b':
                since_timestamp = optarg;
                break;
            case 'c':
                until_timestamp = optarg;
                break;
            case 'd':
                since_cursor = optarg;
                break;
            case 'e':
                until_cursor = optarg;
                break;
            case 's':
                client_socket_address = optarg;
                break;
            case 'f':
                format = optarg;
                break;
            case 'g':
                follow = 1;
                heartbeating = 1;
                break;
            case 'i':
                filter = optarg;
                break;
            case 'j':
                listening = 1;
                break;
            case 'h':
                fprintf(stdout, 
"zmq-journal-gatewayd-client -- receiving logs from zmq-journal-gatewayd over the network\n\n\
Usage: zmq-journal-gatewayd-client [--help] [--socket] [--since] [--until]\n\
                                   [--since_cursor] [--until_cursor] [--at_most]\n\
                                   [--format] [--follow] [--reverse] [--filter]\n\n\
\t--help \t\twill show this\n\
\t--socket \trequires a socket (must be usable by ZeroMQ) to connect to zmq-journal-gatewayd;\n\
\t\t\tdefault is \"tcp://localhost:5555\"\n\
\t--since \trequires a timestamp with a format like \"2014-10-01 18:00:00\"\n\
\t--until \tsee --since\n\
\t--since_cursor \trequires a log cursor, see e.g. 'journalctl -o export'\n\
\t--until_cursor \tsee --since_cursor\n\
\t--at_most \trequires a positive integer N, at most N logs will be sent\n\
\t--format \trequires a format \"export\" or \"plain\", default is \"export\"\n\
\t--follow \tlike 'journalctl -f', follows the remote journal\n\
\t--reverse \treverses the log stream such that newer logs will be sent first\n\
\t--filter \trequires input of the form e.g. \"[[\\\"FILTER_1\\\", \\\"FILTER_2\\\"], [\\\"FILTER_3\\\"]]\"\n\
\t\t\tthis example reprensents the boolean formula \"(FILTER_1 OR FILTER_2) AND (FILTER_3)\"\n\
\t\t\twhereas the content of FILTER_N is matched against the contents of the logs;\n\
\t\t\tExample: --filter [[\\\"PRIORITY=3\\\"]] only shows logs with exactly priority 3 \n\n\
The client is used to connect to zmq-journal-gatewayd via the '--socket' option.\n"
                );
                return;
            case 0:     /* getopt_long() set a variable, just keep going */
                break;
            case ':':   /* missing option argument */
                fprintf(stderr, "%s: option `-%c' requires an argument\n", argv[0], optarg);
                return;
            default:    /* invalid option */
                return;
        }
    } 

    /* initial setup */
    ctx = zctx_new ();
    client = zsocket_new (ctx, ZMQ_ROUTER);
	assert(client);
    //zsocket_set_rcvhwm (client, CLIENT_HWM);

    if(client_socket_address != NULL)
        zsocket_bind (client, client_socket_address);
    else
        zsocket_bind (client, DEFAULT_FRONTEND_SOCKET);

    /* for stopping the client and the gateway handler via keystroke (ctrl-c) */
    signal(SIGINT, stop_handler);

    zmq_pollitem_t items [] = {
        { client, 0, ZMQ_POLLIN, 0 },
    };

    zmsg_t *response;
    int rc;

    uint64_t heartbeat_at = zclock_time () + HEARTBEAT_INTERVAL;                // the absolute time after which a heartbeat is sent
    uint64_t server_heartbeat_at = zclock_time () + SERVER_HEARTBEAT_INTERVAL;  // the absolute time after which a server timeout occours, 
                                                                                // updated with every new message (doesn't need to be a heartbeat)
    initial_time = zclock_time ();

    zhash_t *connections = zhash_new ();
    FILE *sjr;

    if (!getenv(REMOTE_JOURNAL_DIRECTORY)) {
        fprintf(stderr, "%s not specified.\n", REMOTE_JOURNAL_DIRECTORY);
        exit(1);
    }
    const char sjr_cmd_format[] = "/lib/systemd/systemd-journal-remote -o %s/%s.journal -";
    const char *remote_journal_directory = getenv(REMOTE_JOURNAL_DIRECTORY);
    assert(remote_journal_directory);

    /* receive logs, initiate connections to new sources, respond to heartbeats */
    while ( active ){
        rc=zmq_poll (items, 1, 100);
        if( rc==-1 )
            //some error occured
            break;
        if(items[0].revents & ZMQ_POLLIN){
            response = zmsg_recv(client);
			zframe_t *client_ID = zmsg_pop (response);
            assert(client_ID);
            char* client_key = zframe_strhex(client_ID);
            sjr = zhash_lookup (connections, client_key);
            if ( sjr == NULL ){
                char pathtojournalfile[256];
                const char *journalname = zframe_strhex(client_ID);
                assert(strlen(remote_journal_directory) + strlen(journalname) +
						sizeof(sjr_cmd_format)<sizeof(pathtojournalfile));
                sprintf (pathtojournalfile, sjr_cmd_format, remote_journal_directory, journalname);
                fprintf(stderr, "DBG: opening journal-remote: [%s]\n", pathtojournalfile);
                sjr = popen(pathtojournalfile, "w");
                assert(sjr);
                fprintf(stderr, "DBG: opnened journal-remote: %i\n", fileno(sjr));
                zhash_insert(connections, client_key, sjr);
            }
            fprintf(stderr, "DBG: into response_handler\n");
            rc = response_handler(client_ID, response, sjr);
            fprintf(stderr, "DBG: before flushing\n");
            fflush(sjr);
			fprintf(stderr, "flushed %i\n", fileno(sjr));
            zmsg_destroy (&response);
            /* end of log stream and not listening for more OR did an error occur? */
            if ( rc==1 || rc==-1 ){
                break;
            }
            if ( rc==2 ){
                pclose(sjr);
                zhash_delete(connections, client_key);
            }
        }
    }

    sjr = zhash_first(connections);
    while( sjr != NULL ){
        pclose(sjr);
        zhash_delete(connections, zhash_cursor(connections));
        sjr=zhash_first(connections);
    }
    /* clear everything up */
    zhash_destroy(&connections);
    zsocket_destroy (ctx, client);
    zctx_destroy (&ctx);

    //benchmark(initial_time, log_counter);
    return 0;
}
