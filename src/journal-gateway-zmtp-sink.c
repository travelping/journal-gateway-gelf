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
#include <sys/stat.h>
#include <errno.h>

#include "uthash/uthash.h"
#include "journal-gateway-zmtp.h"
#include "journal-gateway-zmtp-control.h"

#define KEYDATA(KEY) .key=KEY, .keylen=sizeof(KEY)

static zctx_t *ctx;
static void *client, *router_control;
uint64_t initial_time;
int heartbeating = HEARTBEATING;

/* cli arguments */
int     reverse=0, at_most=-1, follow=0, listening=0;
char    *since_timestamp=NULL, *until_timestamp=NULL, *client_socket_address=NULL, *control_socket_address=NULL,
        *format=NULL, *since_cursor=NULL, *until_cursor=NULL, *filter=NULL,
        *remote_journal_directory=NULL;

// constants
const char sjr_cmd_format[] = "/lib/systemd/systemd-journal-remote -o %s/%s.journal -";

typedef struct {
    char            *client_key;
    zframe_t        *id_frame;
    FILE            *sjr;
    time_t          time_last_message;
    UT_hash_handle  hh; /*requirement for uthash*/
}Connection;

// hash to note every incomming connection
Connection *connections = NULL;

// structures for controlhandling

typedef enum {
    FT_REVERSE,
    FT_AT_MOST,
    FT_SINCE_TIMESTAMP,
    FT_UNTIL_TIMESTAMP,
    FT_SINCE_CURSOR,
    FT_UNTIL_CURSOR,
    FT_FOLLOW,
    FT_FILTER,
    FT_LISTEN,
    SET_EXPOSED_PORT,
    SET_LOG_DIRECTORY,
    SHOW_FILTER,
    SHOW_SOURCES,
    CTRL_SND_QUERY,
    CTRL_SHUTDOWN,
    SHOW_HELP
} opcode;

struct Command{
    opcode id;
    const char *key;
    unsigned int keylen;
};

static struct Command valid_commands[] = {
    {.id = FT_REVERSE, KEYDATA("reverse")},
    {.id = FT_AT_MOST, KEYDATA("at_most")},
    {.id = FT_SINCE_TIMESTAMP, KEYDATA("since_timestamp")},
    {.id = FT_UNTIL_TIMESTAMP, KEYDATA("until_timestamp")},
    {.id = FT_SINCE_CURSOR, KEYDATA("since_cursor")},
    {.id = FT_UNTIL_CURSOR, KEYDATA("until_cursor")},
    {.id = FT_FOLLOW, KEYDATA("follow")},
    {.id = FT_FILTER, KEYDATA("filter")},
    {.id = FT_LISTEN, KEYDATA("listen")},
    {.id = SET_EXPOSED_PORT, KEYDATA("set_exposed_port")},
    {.id = SET_LOG_DIRECTORY, KEYDATA("set_log_directory")},
    {.id = SHOW_FILTER, KEYDATA("show_filter")},
    {.id = SHOW_SOURCES, KEYDATA("show_sources")},
    {.id = CTRL_SND_QUERY, KEYDATA("send_query")},
    {.id = CTRL_SHUTDOWN, KEYDATA("shutdown")},
    {.id = SHOW_HELP, KEYDATA("help")}
};

int execute_command(opcode command_id, json_t *command_arg, zframe_t **response);

int get_command_id_by_key(const char *inp_key, opcode *result);

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

//helper for HASH
/* removes item from hash */
void con_hash_delete(Connection **hash, Connection *item){
    HASH_DEL(*hash, item);
    free(item->client_key);
    zframe_destroy(&(item->id_frame));
    pclose(item->sjr);
    free(item);
}

FILE* create_log_filestream(char *client_key){
    FILE *ret = NULL;
    char pathtojournalfile[256];
    const char *journalname = client_key;
    assert(strlen(remote_journal_directory) + strlen(journalname) +
        sizeof(sjr_cmd_format) < sizeof(pathtojournalfile));
    sprintf (pathtojournalfile, sjr_cmd_format, remote_journal_directory, journalname);
    ret = popen(pathtojournalfile, "w");
    assert(ret);
    return ret;
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
        json_t *json_filter = json_loads(filter, JSON_REJECT_DUPLICATES, NULL);
        json_object_set_new(query, "field_matches", json_filter);
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
    UNUSED(dummy);
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
        }
    }while( strcmp( frame_string, STOP ) != 0 );
    if (frame_string != NULL)
        free(frame_string);
    active = false;
}

/* Do sth with the received (log)message */
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
            if (!listening) {
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
        else if( memcmp( frame_data, STOP, strlen(STOP) ) == 0 ){
            NULL;
        }
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
            Connection *lookup = NULL;
            HASH_FIND_STR( connections, client_ID, lookup );
            con_hash_delete( &connections, lookup );
            ret=2;
        }
        else{
			assert(((char*)frame_data)[0] == '_');
            int fd = fileno(sjr);
			fflush(stderr);
            write(fd, frame_data, frame_size);
            write(fd, "\n", 1);
        }
        zframe_destroy (&frame);
    }while(more);

    free(client_ID);

    return ret;
}

/* handle received control messages */
int control_handler (zmsg_t *command_msg, zframe_t *cid){
    int ret=1;
    zframe_t *frame;
    int more, rc;
    char *client_ID = zframe_strhex(cid);

    do{
        frame = zmsg_pop (command_msg);
        more = zframe_more (frame);
        char *json_string = zframe_strdup(frame);
        assert(json_string);
        // decode received command
        json_t *control_package = json_loads(json_string, 0, NULL);
        assert(control_package);
        free(json_string);

        // iterate over the packed commands (though the package should only contain one command)
        void *iter = json_object_iter(control_package);
        while(iter){
            const char *command_key = json_object_iter_key(iter);
            assert(command_key);
            opcode command_id;
            rc = get_command_id_by_key(command_key, &command_id);

            zmsg_t *m = zmsg_new(); assert(m);
            zframe_t *response = NULL;
            //command was valid
            if( rc==1 ){
                json_t* command_arg = json_object_iter_value(iter);
                // now do the appropriate action with this commands
                rc = execute_command(command_id, command_arg, &response);
                //if rc==0 the command execution failed unexpectedly, this shouldn't happen in this if branch
                assert(rc);
                zmsg_push(m, response);
                zmsg_push(m, cid);
                zmsg_send(&m, router_control);
            }
            //command was not valid
            else{
                response = zframe_new(CTRL_UKCOM, strlen(CTRL_UKCOM));
                zmsg_push(m, response);
                zmsg_push(m, cid);
                zmsg_send(&m, router_control);
            }

            iter = json_object_iter_next(control_package, iter);
        }
        zframe_destroy (&frame);
    }while(more);

    // cleanup
    free(client_ID);

    return ret;
}

/* control API */

/* changing the exposed port and signalling all logged on sources about the change */
int set_exposed_port(int port){
    int ret = 0;
    // check for valid port
    if(port <= 1023 || 65536 <= port){
        ret = -1;
        fprintf(stderr, "%s\n", "Port not set, please choose a valid one ( >1023, <65536 )");
        return ret;
    }

    // actual change of the port
    int rc;
    char *endpoint[256];
    size_t endpoint_len = sizeof(endpoint);
    rc = zmq_getsockopt(client, ZMQ_LAST_ENDPOINT, endpoint, &endpoint_len);
    assert ( rc==0 );
    rc = zsocket_unbind(client, client_socket_address);
    if(rc==-1){
    perror("zsocket_unbind");
    }
    assert ( rc==0 );
    sprintf(client_socket_address, "tcp://127.0.0.1:%d", port);
    rc = zsocket_bind(client, client_socket_address);
    assert( rc );
    sd_journal_print(LOG_INFO, "Changed exposed port to %s", client_socket_address);

    return ret;
}

/* changing the directory, in which the remote journals are stored*/
int set_log_directory(char *new_directory){
    int ret = 1;

    // create specified directory with rwxrw-rw-
    ret = mkdir(new_directory, 0766);
    if (ret == -1){
        switch(errno){
            case EEXIST:
                // directory already exists, everythings fine
                ret = 1;
                break;
            default:
                // some other error occured
                fprintf(stderr, "Error while creating the directory, errno: %d \n", errno);
                return -1;
        }
    }
    free(remote_journal_directory);
    remote_journal_directory = new_directory;
    // adjust filestreams
    Connection *i, *tmp;
    HASH_ITER(hh, connections, i, tmp){
        pclose(i->sjr);
        i->sjr = create_log_filestream(i->client_key);
    }

    return ret;
}

/*
    returns the conected sources as a string, separated by newline
*/
void show_sources(char *ret){
    //todo check for to long output
    int length = 0;
    Connection *i, *tmp;
    if( 0 < HASH_COUNT(connections) ){
        HASH_ITER(hh, connections, i, tmp){
            length += sprintf(ret+length, "%s\n", i->client_key);
        }
    }
    else{
        sprintf(ret, "No Sources\n");
    }
}

/*
    returns the set filters as a string, filters are seperated by newline
    reverse = 0
    at_most = -1
    ...
*/
void show_filter(char *ret){
    //todo check for to long output
    int length = 0;
    length += sprintf(ret+length, "reverse = %d\n", reverse);
    length += sprintf(ret+length, "at_most = %d\n", at_most);
    length += sprintf(ret+length, "since_timestamp = %s\n", since_timestamp);
    length += sprintf(ret+length, "until_timestamp = %s\n", until_timestamp);
    length += sprintf(ret+length, "since_cursor = %s\n", since_cursor);
    length += sprintf(ret+length, "until_cursor = %s\n", until_cursor);
    length += sprintf(ret+length, "follow = %d\n", follow);
    length += sprintf(ret+length, "filter = %s\n", filter);
    length += sprintf(ret+length, "listen = %d\n", listening);
}

// shows a help dialogue
void show_help(char *ret){
    sprintf(ret,
"Usage: Type in one of the following commands and \n\
optional arguments (space separated), confirm your input by pressing enter\n\n\
\thelp\t\t\twill show this\n\
\tsince_timestamp\t\trequires a timestamp with a format like \"2014-10-01 18:00:00\"\n\
\tuntil_timestamp\t\tsee --since_timestamp\n\
\tsince_cursor\t\trequires a log cursor, see e.g. 'journalctl -o export'\n\
\tuntil_cursor\t\tsee --since_cursor\n\
\tat_most\t\t\trequires a positive integer N, at most N logs will be sent\n\
\tfollow\t\t\tlike 'journalctl -f', follows the remote journal\n\
\tlisten\t\t\tthe sink waits indefinitely for incomming messages from sources\n\
\treverse\t\t\treverses the log stream such that newer logs will be sent first\n\
\tfilter\t\t\trequires input of the form e.g. \"[[\"FILTER_1\", \"FILTER_2\"], [\"FILTER_3\"]]\"\n\
\t\t\t\tthis example reprensents the boolean formula \"(FILTER_1 OR FILTER_2) AND (FILTER_3)\"\n\
\t\t\t\twhereas the content of FILTER_N is matched against the contents of the logs;\n\
\t\t\t\tExample: --filter [[\"PRIORITY=3\"]] only shows logs with exactly priority 3 \n\
\tshow_filter\t\tshows the current filters (see above)\n\
\tset_exposed_port\trequires a valid tcp port\n\
\tset_log_directory\trequires a path to a directory\n\
\tshow_sources\t\tshows the connected sources\n\
\tsend_query\t\ttriggers all sources to send logs coresponding to the current set of filters\n\
\tshutdown\t\tstops the gateway\
\n\n"
    );
}

void send_stop(){
    char *query_string = build_query_string();
    zmsg_t *m;
    zframe_t *queryframe, *cid;
    Connection *i, *tmp;
    HASH_ITER(hh, connections, i, tmp){
        m = zmsg_new(); assert(m);
        queryframe = zframe_new(STOP, strlen(STOP));
        assert(queryframe);
        // duplicate id_frame so it won't be destroyed
        cid = zframe_dup(i->id_frame);
        assert(cid);
        zmsg_push(m, queryframe);
        zmsg_push(m, cid);
        zmsg_send (&m, client);
    }
    free(query_string);
}

void send_query(){
    //waiting for source to finish old query
    sleep(1);
    send_stop();
    //waiting for source to finish old query
    sleep(1);
    char *query_string = build_query_string();
    zmsg_t *m;
    zframe_t *queryframe, *cid;
    Connection *i, *tmp;
    HASH_ITER(hh, connections, i, tmp){
        m = zmsg_new(); assert(m);
        queryframe = zframe_new(query_string, strlen(query_string));
        assert(queryframe);
        // duplicate id_frame so it won't be destroyed
        cid = zframe_dup(i->id_frame);
        assert(cid);
        zmsg_push(m, queryframe);
        zmsg_push(m, cid);
        zmsg_send (&m, client);
    }
    free(query_string);
}

/*
    searches for coresponding id to the inserted filter key
    the id is returned in *result
    the return value is 1 on success and 0 else
*/
int get_command_id_by_key(const char *inp_key, opcode *result){
    size_t i;
    for(i = 0; i < sizeof(valid_commands)/sizeof(valid_commands[0]); i++){
        if(strncmp(inp_key, valid_commands[i].key, valid_commands[i].keylen) == 0){
            *result = valid_commands[i].id;
            return 1;
        }
    }

    return 0;
}

// json helper

char* get_arg_string(json_t *arg){
    return strdup(json_string_value(arg));
}

int get_arg_int(json_t *arg){
    int ret = 0;
    ret = atoi(json_string_value(arg));
    return ret;
}


/*
    apply the specified command, encrypted as ID
    returns 1 on success and 0 else
*/
int execute_command(opcode command_id, json_t *command_arg, zframe_t **response){
    int port;
    char *dir, stringh[2048];

    switch (command_id){
        case FT_REVERSE:
            reverse = get_arg_int(command_arg);
            *response = zframe_new(CTRL_ACCEPTED,strlen(CTRL_ACCEPTED));
            break;
        case FT_AT_MOST:
            at_most = get_arg_int(command_arg);
            *response = zframe_new(CTRL_ACCEPTED,strlen(CTRL_ACCEPTED));
            break;
        case FT_SINCE_TIMESTAMP:
            free(since_timestamp);
            since_timestamp = get_arg_string(command_arg);
            *response = zframe_new(CTRL_ACCEPTED,strlen(CTRL_ACCEPTED));
            break;
        case FT_UNTIL_TIMESTAMP:
            free(until_timestamp);
            until_timestamp = get_arg_string(command_arg);
            *response = zframe_new(CTRL_ACCEPTED,strlen(CTRL_ACCEPTED));
            break;
        case FT_SINCE_CURSOR:
            free(since_cursor);
            since_cursor = get_arg_string(command_arg);
            *response = zframe_new(CTRL_ACCEPTED,strlen(CTRL_ACCEPTED));
            break;
        case FT_UNTIL_CURSOR:
            free(until_cursor);
            until_cursor = get_arg_string(command_arg);
            *response = zframe_new(CTRL_ACCEPTED,strlen(CTRL_ACCEPTED));
            break;
        case FT_FOLLOW:
            follow = get_arg_int(command_arg);
            *response = zframe_new(CTRL_ACCEPTED,strlen(CTRL_ACCEPTED));
            break;
        case FT_FILTER:
            free(filter);
            filter = get_arg_string(command_arg);
            *response = zframe_new(CTRL_ACCEPTED,strlen(CTRL_ACCEPTED));
            break;
        case FT_LISTEN:
            listening = get_arg_int(command_arg);
            *response = zframe_new(CTRL_ACCEPTED,strlen(CTRL_ACCEPTED));
            break;
        case SET_EXPOSED_PORT:
            port = get_arg_int(command_arg);
            set_exposed_port(port);
            *response = zframe_new(CTRL_ACCEPTED,strlen(CTRL_ACCEPTED));
            break;
        case SET_LOG_DIRECTORY:
            dir = get_arg_string(command_arg);
            set_log_directory(dir);
            *response = zframe_new(CTRL_ACCEPTED,strlen(CTRL_ACCEPTED));
            break;
        case SHOW_FILTER:
            show_filter(&stringh[0]);
            *response = zframe_new(stringh,strlen(stringh));
            break;
        case SHOW_SOURCES:
            show_sources(&stringh[0]);
            *response = zframe_new(stringh,strlen(stringh));
            break;
        case SHOW_HELP:
            show_help(&stringh[0]);
            *response = zframe_new(stringh,strlen(stringh));
            break;
        case CTRL_SND_QUERY:
            send_query();
            *response = zframe_new(CTRL_ACCEPTED,strlen(CTRL_ACCEPTED));
            break;
        case CTRL_SHUTDOWN:
            stop_handler(0);
            *response = zframe_new(CTRL_ACCEPTED,strlen(CTRL_ACCEPTED));
            break;
        default:
            return 0;
    }

    return 1;
}

#ifndef TEST
int main ( int argc, char *argv[] ){

    struct option longopts[] = {
        { "reverse",        no_argument,            &reverse,     1   },
        { "at_most",        required_argument,      NULL,         'a' },
        { "since",          required_argument,      NULL,         'b' },
        { "until",          required_argument,      NULL,         'c' },
        { "since_cursor",   required_argument,      NULL,         'd' },
        { "until_cursor",   required_argument,      NULL,         'e' },
        { "follow",         no_argument,            NULL,         'g' },
        { "help",           no_argument,            NULL,         'h' },
        { "filter",         required_argument,      NULL,         'i' },
        { "listen",         no_argument,            NULL,         'j' },
        { 0, 0, 0, 0 }
    };

    int c;
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
Usage: journal-gateway-zmtp-sink   [--help] [--since] [--until]\n\
                                   [--since_cursor] [--until_cursor] [--at_most]\n\
                                   [--follow] [--reverse] [--filter]\n\n\
\t--help \t\twill show this\n\
\t--since \trequires a timestamp with a format like \"2014-10-01 18:00:00\"\n\
\t--until \tsee --since\n\
\t--since_cursor \trequires a log cursor, see e.g. 'journalctl -o export'\n\
\t--until_cursor \tsee --since_cursor\n\
\t--at_most \trequires a positive integer N, at most N logs will be sent\n\
\t--follow \tlike 'journalctl -f', follows the remote journal\n\
\t--listen \tthe sink waits indefinitely for incomming messages from sources\n\
\t--reverse \treverses the log stream such that newer logs will be sent first\n\
\t--filter \trequires input of the form e.g. \"[[\\\"FILTER_1\\\", \\\"FILTER_2\\\"], [\\\"FILTER_3\\\"]]\"\n\
\t\t\tthis example reprensents the boolean formula \"(FILTER_1 OR FILTER_2) AND (FILTER_3)\"\n\
\t\t\twhereas the content of FILTER_N is matched against the contents of the logs;\n\
\t\t\tExample: --filter [[\\\"PRIORITY=3\\\"]] only shows logs with exactly priority 3 \n\n\
The sink is used to wait for incomming messages from journal-gateway-zmtp-source via exposing a socket.\n\
Set this socket via setting EXPOSED_SOCKET environment variable (must be usable by ZeroMQ).\n\
Default is tcp://localhost:5555\n\n"
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

    remote_journal_directory = strdup(getenv(REMOTE_JOURNAL_DIRECTORY));
    if (!(remote_journal_directory)) {
        fprintf(stderr, "%s not specified.\n", REMOTE_JOURNAL_DIRECTORY);
        exit(1);
    }
    client_socket_address = getenv(EXPOSED_SOCKET);
    if (!(client_socket_address)) {
        fprintf(stderr, "%s not specified.\n", EXPOSED_SOCKET);
        exit(1);
    }

    int major, minor, patch;
    zmq_version(&major, &minor, &patch);

    printf("Uses ZMQ version %d.%d.%d\n", major, minor, patch);

    /* ensure existence of a machine id */
    check_machine_id();

    /* initial setup of connection  */
    ctx = zctx_new();
    client = zsocket_new (ctx, ZMQ_ROUTER);
    assert(client);
    //zsocket_set_rcvhwm (client, CLIENT_HWM);

    /* for stopping the client and the gateway handler via keystroke (ctrl-c) */
    signal(SIGINT, stop_handler);

    int rc;
    if(client_socket_address != NULL)
        rc = zsocket_bind (client, client_socket_address);
    else
        rc = zsocket_bind (client, DEFAULT_FRONTEND_SOCKET);
    assert(rc);

    router_control = zsocket_new(ctx, ZMQ_ROUTER);
    assert(router_control);

    if(control_socket_address != NULL)
        rc = zsocket_bind (router_control, control_socket_address);
    else
        rc = zsocket_bind (router_control, DEFAULT_CONTROL_SOCKET);
    assert(rc);

    zmq_pollitem_t items [] = {
        { client, 0, ZMQ_POLLIN, 0 },
        { router_control, 0, ZMQ_POLLIN, 0 },
    };

    zmsg_t *response;

    initial_time = zclock_time ();
    /* timer for timeouts */
    time_t last_check=0;
    Connection *lookup;
    zframe_t *client_ID;
    char *client_key;

    /* receive controls or logs, initiate connections to new sources */
    while ( active ){
        rc=zmq_poll (items, 2, 100);
        /* receive logs */
        if(items[0].revents & ZMQ_POLLIN){
            response = zmsg_recv(client);
            client_ID = zmsg_pop (response);
            assert(client_ID);
            client_key = zframe_strhex(client_ID);
            lookup = NULL;
            HASH_FIND_STR( connections, client_key, lookup );
            /*new connection*/
            if ( lookup == NULL ){
                lookup = (Connection *) malloc( sizeof(Connection) );
                assert(lookup);
                lookup->sjr = create_log_filestream(client_key);
                lookup->id_frame = zframe_dup(client_ID);
                lookup->client_key=client_key;
                HASH_ADD_STR(connections, client_key, lookup);
            }
            free(client_key);
            lookup->time_last_message = get_clock_time();
            rc = response_handler(client_ID, response, lookup->sjr);
            fflush(lookup->sjr);
            zmsg_destroy (&response);
            /* end of log stream and not listening for more OR did an error occur? */
            if ( rc==1 || rc==-1 ){
                break;
            }
            // a source logged off
            if ( rc==2 ){
                NULL;
            }
        }
        /* receive controls */
        if(items[1].revents & ZMQ_POLLIN){
            response = zmsg_recv(router_control);
            client_ID = zmsg_pop (response);
            assert(client_ID);
            rc = control_handler(response, client_ID);
            assert(rc);
            zmsg_destroy (&response);
        }
        time_t now = get_clock_time();
        if ( difftime(now, last_check) > 60 ){
            last_check=now;
            Connection *i, *tmp;
            HASH_ITER(hh, connections, i, tmp){
                if (difftime(now, i->time_last_message)>60*60){
                    /* remove i from connections */
                    con_hash_delete(&connections, i);
                }
            }
        }
    }
    /* clear everything up */
    zsocket_destroy (ctx, client);
    zsocket_destroy (ctx, router_control);
    zctx_destroy (&ctx);

    //benchmark(initial_time, log_counter);
    return 0;
}
#endif
