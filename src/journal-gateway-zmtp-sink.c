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
#include <time.h>
#include <systemd/sd-journal.h>
#include <systemd/sd-id128.h>

#include "uthash/uthash.h"
#include "journal-gateway-zmtp.h"

static zctx_t *ctx;
static void *client;
uint64_t initial_time;
int log_counter = 0;
int heartbeating = HEARTBEATING;

/* cli arguments */
int     reverse=0, at_most=-1, follow=0, listening=0;
char    *since_timestamp=NULL, *until_timestamp=NULL, *client_socket_address=NULL, *format=NULL,
        *since_cursor=NULL, *until_cursor=NULL, *filter=NULL;

typedef struct {
    char            *client_key;
    FILE            *sjr;
    time_t          time_last_message;
    UT_hash_handle  hh; /*requirement for uthash*/
}Connection;

time_t get_clock_time(){
    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);
    return time.tv_sec;
}

/* this checks whether a machine id exists */
void check_machine_id(){
    sd_id128_t ret;
    assert ( sd_id128_get_machine(&ret) == 0 );
}

/* removes item from hash */
void con_hash_delete(Connection *hash, Connection *item){
    HASH_DEL(hash, item);
    free(item->client_key);
    pclose(item->sjr);
    free(item);
}

char* make_json_timestamp(char *timestamp){
    if (timestamp == NULL) {
        return NULL;
	}

	if (0 == strcmp("now", timestamp)) {
		return "now";
	}

    char *json_timestamp = (char *) malloc(sizeof(char) * 21);
    json_timestamp[0] = '\0';
    strtok(timestamp, " ");
    strcat(json_timestamp, timestamp);
    strcat(json_timestamp, "T");
    strtok(NULL, " ");
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
    printf("<< sent %d logs in %"PRIu64" seconds ( %" PRIu64 " logs/sec ) >>\n",
        log_counter, time_diff_sec, log_rate_sec);
}

static bool active = true;
void stop_handler(int dummy) {
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
    active = false;
}

/* Do sth with the received message */
int response_handler(zframe_t* cid, zmsg_t *response, FILE *sjr){
    zframe_t *frame;
    void *frame_data;
    size_t frame_size;
    int more;
    int ret = 0;
    char* client_ID = zframe_strhex(cid);

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
            sd_journal_print(LOG_INFO, "gateway has a new source, ID: %s", client_ID);
        }
        else if( memcmp( frame_data, LOGOFF, strlen(LOGOFF) ) == 0 ){
            sd_journal_print(LOG_INFO, "one source of the gateway logged off, ID: %s", client_ID);
            ret=2;
        }
        else{
			assert(((char*)frame_data)[0] == '_');
            int fd = fileno(sjr);

			fflush(stderr);
            write(fd, frame_data, frame_size);

            write(fd, "\n", 1);
            log_counter++;
        }
        zframe_destroy (&frame);
    }while(more);

    free(client_ID);

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

    const char *remote_journal_directory = getenv(REMOTE_JOURNAL_DIRECTORY);
    if (!(remote_journal_directory)) {
        fprintf(stderr, "%s not specified.\n", REMOTE_JOURNAL_DIRECTORY);
        exit(1);
    }
    const char sjr_cmd_format[] = "/lib/systemd/systemd-journal-remote -o %s/%s.journal -";


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
"journal-gateway-zmtp-sink -- receiving logs from journal-gateway-zmtp-source over the network\n\n\
Usage: journal-gateway-zmtp-sink   [--help] [--socket] [--since] [--until]\n\
                                   [--since_cursor] [--until_cursor] [--at_most]\n\
                                   [--format] [--follow] [--reverse] [--filter]\n\n\
\t--help \t\twill show this\n\
\t--socket \trequires a socket (must be usable by ZeroMQ) to bind on;\n\
\t\t\tdefault is \"tcp://localhost:5555\"\n\
\t--since \trequires a timestamp with a format like \"2014-10-01 18:00:00\"\n\
\t--until \tsee --since\n\
\t--since_cursor \trequires a log cursor, see e.g. 'journalctl -o export'\n\
\t--until_cursor \tsee --since_cursor\n\
\t--at_most \trequires a positive integer N, at most N logs will be sent\n\
\t--format \trequires a format \"export\" or \"plain\", default is \"export\"\n\
\t--follow \tlike 'journalctl -f', follows the remote journal\n\
\t--listen \tthe sink waits indefinitely for incomming messages from sources\n\
\t--reverse \treverses the log stream such that newer logs will be sent first\n\
\t--filter \trequires input of the form e.g. \"[[\\\"FILTER_1\\\", \\\"FILTER_2\\\"], [\\\"FILTER_3\\\"]]\"\n\
\t\t\tthis example reprensents the boolean formula \"(FILTER_1 OR FILTER_2) AND (FILTER_3)\"\n\
\t\t\twhereas the content of FILTER_N is matched against the contents of the logs;\n\
\t\t\tExample: --filter [[\\\"PRIORITY=3\\\"]] only shows logs with exactly priority 3 \n\n\
The sink is used to wait for incomming messages from journal-gateway-zmtp-source via the '--socket' option.\n"
                );
                return 0;
            case 0:     /* getopt_long() set a variable, just keep going */
                break;
            case ':':   /* missing option argument */
                fprintf(stderr, "%s: option `-%s' requires an argument\n", argv[0], optarg);
                return 0;
            default:    /* invalid option */
                return 0;
        }
    }

    /* ensure existence of a machine id */
    check_machine_id();

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

    initial_time = zclock_time ();

    //  zhash_t *connections = zhash_new ();
    Connection *connections = NULL;
    Connection *lookup;

    /* timer for timeouts */
    time_t last_check=0;

    /* receive logs, initiate connections to new sources, respond to heartbeats */
    while ( active ){
        rc=zmq_poll (items, 1, 60000);
        if(items[0].revents & ZMQ_POLLIN){
            response = zmsg_recv(client);
            zframe_t *client_ID = zmsg_pop (response);
            assert(client_ID);
            char* client_key = zframe_strhex(client_ID);
            // lookup = zhash_lookup (connections, client_key);
            HASH_FIND_STR( connections, client_key, lookup );
            /*new connection*/
            if ( lookup == NULL ){
                lookup = (Connection *) malloc( sizeof(Connection) );
                char pathtojournalfile[256];
                const char *journalname = client_key;
                assert(strlen(remote_journal_directory) + strlen(journalname) +
                        sizeof(sjr_cmd_format)<sizeof(pathtojournalfile));
                sprintf (pathtojournalfile, sjr_cmd_format, remote_journal_directory, journalname);
                lookup->sjr = popen(pathtojournalfile, "w");
                lookup->client_key=client_key;
                assert(lookup->sjr);
                // zhash_insert(connections, client_key, lookup);
                HASH_ADD_STR(connections, client_key, lookup);
            }
            else{
                free(client_key);
            }
            lookup->time_last_message = get_clock_time();
            rc = response_handler(client_ID, response, lookup->sjr);
            fflush(lookup->sjr);
            zmsg_destroy (&response);
            /* end of log stream and not listening for more OR did an error occur? */
            if ( rc==1 || rc==-1 ){
                break;
            }
            if ( rc==2 ){
                pclose(lookup->sjr);
                HASH_DEL(connections, lookup);
            }
        }
        time_t now = get_clock_time();
        if ( difftime(now, last_check) > 60 ){
            last_check=now;
            Connection *i, *tmp;
            HASH_ITER(hh, connections, i, tmp){
                if (difftime(now, i->time_last_message)>60*60){
                    /* remove i from connections */
                    con_hash_delete(connections, i);
                }
            }
        }
    }
    /* clear everything up */
    zsocket_destroy (ctx, client);
    zctx_destroy (&ctx);

    //benchmark(initial_time, log_counter);
    return 0;
}
