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
int     reverse=0, at_most=-1, follow=0;
char    *since_timestamp=NULL, *until_timestamp=NULL, *client_socket_address=NULL, *format=NULL,
        *since_cursor=NULL, *until_cursor=NULL;

char* make_json_timestamp(char *timestamp){
    if (timestamp == NULL)
        return NULL;
    char *json_timestamp = (char *) malloc(sizeof(char) * 20);
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
    if (reverse == 1) json_object_set(query, "reverse", json_true());
    if (at_most >= 0) json_object_set(query, "at_most", json_integer(at_most));
    if (follow == 1) json_object_set(query, "follow", json_true());
    if (format != NULL) json_object_set(query, "format", json_string(format));
    char* json_since = make_json_timestamp(since_timestamp);
    if (json_since != NULL) {
        json_object_set(query, "since_timestamp", json_string(json_since));
        free(json_since);
    }
    char* json_until = make_json_timestamp(until_timestamp);
    if (json_until != NULL) { 
        json_object_set(query, "until_timestamp", json_string(json_until));
        free(json_until);
    }
    if (since_cursor != NULL) json_object_set(query, "since_cursor", json_string(since_cursor));
    if (until_cursor != NULL) json_object_set(query, "until_cursor", json_string(until_cursor));
    return json_dumps(query, JSON_ENCODE_ANY);
}

/* for measuring performance of the gateway */
void benchmark(uint64_t initial_time, int log_counter) {
    uint64_t current_time = zclock_time ();
    uint64_t time_diff_sec = (current_time - initial_time)/1000;
    uint64_t log_rate_sec = log_counter / time_diff_sec;
    //printf("<< sent %d logs in %d seconds ( %d logs/sec ) >>\n", log_counter, time_diff_sec, log_rate_sec);
}

static bool active = true;
void stop_handler(int dummy) {
    int rc;
    zmq_pollitem_t items [] = {
        { client, 0, ZMQ_POLLIN, 0 },
    };

    //printf("\n<< sending STOP ... >>\n");
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

    benchmark(initial_time, log_counter);
    //printf("<< STOPPED >>\n");

    /* stop the client */
    active = false;
}

/* Do sth with the received message */
int response_handler(zmsg_t *response){
    zframe_t *frame;
    void *frame_data;
    size_t frame_size;
    int more;

    do{
        frame = zmsg_pop (response);
        frame_size = zframe_size(frame);
        more = zframe_more (frame);
        frame_data = zframe_data(frame);
        if( memcmp( frame_data, END, strlen(END) ) == 0 ){
            //printf("<< got all logs >>\n");
            zframe_destroy (&frame);
            return 1;
        }
        else if( memcmp( frame_data, ERROR, strlen(ERROR) ) == 0 ){
            //printf("<< an error occoured - invalid json query string? >>\n");
            zframe_destroy (&frame);
            return -1;
        }
        else if( memcmp( frame_data, HEARTBEAT, strlen(HEARTBEAT) ) == 0 ) NULL;
        //    printf("<< HEARTBEAT >>\n");
        else if( memcmp( frame_data, TIMEOUT, strlen(TIMEOUT) ) == 0 ) NULL;
        //    printf("<< server got no heartbeat >>\n");
        else if( memcmp( frame_data, READY, strlen(READY) ) == 0 ) NULL;
        //    printf("<< gateway accepted query >>\n\n");
        else{
            write(1, "\n", 1);
            write(1, frame_data, frame_size);
            log_counter++;
        }
        zframe_destroy (&frame);
    }while(more);

    return 0;
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
        { "socket",         required_argument,      NULL,         's' },
        { 0, 0, 0, 0 }
    };

    int c;
    while((c = getopt_long(argc, argv, "s:a:b:c:f:", longopts, NULL)) != -1) {
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
            case 0:     /* getopt_long() set a variable, just keep going */
                break;
            case ':':   /* missing option argument */
                fprintf(stderr, "%s: option `-%c' requires an argument\n",
                        argv[0], optarg);
                break;
            default:    /* invalid option */
                break;
        }
    } 

    char *query_string = build_query_string();

    /* initial setup */
    ctx = zctx_new ();
    client = zsocket_new (ctx, ZMQ_DEALER);
    zsocket_set_rcvhwm (client, CLIENT_HWM);

    if(client_socket_address != NULL)
        zsocket_connect (client, client_socket_address);
    else
        zsocket_connect (client, DEFAULT_CLIENT_SOCKET);

    /* for stopping the client and the gateway handler via keystroke (ctrl-c) */
    signal(SIGINT, stop_handler);

    /* send query */
    zstr_send (client, query_string);

    zmq_pollitem_t items [] = {
        { client, 0, ZMQ_POLLIN, 0 },
    };

    zmsg_t *response;
    int rc;

    uint64_t heartbeat_at = zclock_time () + HEARTBEAT_INTERVAL;                // the absolute time after which a heartbeat is sent
    uint64_t server_heartbeat_at = zclock_time () + SERVER_HEARTBEAT_INTERVAL;  // the absolute time after which a server timeout occours, 
                                                                                // updated with every new message (doesn't need to be a heartbeat)
    initial_time = zclock_time ();
                                                                                
    /* receive response while sending heartbeats (if necessary) */
    while (active) {

        rc = zmq_poll (items, 1, HEARTBEAT_INTERVAL * ZMQ_POLL_MSEC);
        if( rc == 0 && heartbeating ){
            /* no message from server so far => send heartbeat */
            zstr_send (client, HEARTBEAT);
            heartbeat_at = zclock_time () + HEARTBEAT_INTERVAL;
        }
        else if ( rc > 0 ) 
            /* message from server arrived => update the timeout interval */
            server_heartbeat_at = zclock_time () +  SERVER_HEARTBEAT_INTERVAL;
        else if( rc == -1 ) 
            /* something went wrong */
            break;

        if(zclock_time () >= server_heartbeat_at){ 
            //printf("<< SERVER TIMEOUT >>\n");
            break;
        }

        /* receive message and do sth with it */
        if (items[0].revents & ZMQ_POLLIN){ 
            response = zmsg_recv(client);
            rc = response_handler(response);
            zmsg_destroy (&response);
            /* end of log stream? */
            if (rc != 0)
                break;
        }

        /* the server also expects heartbeats while he is sending messages */
        if (zclock_time () >= heartbeat_at && heartbeating) {
            zstr_send (client, HEARTBEAT);
            heartbeat_at = zclock_time () + HEARTBEAT_INTERVAL;
        }
    }

    printf("\n");

    /* clear everything up */
    zsocket_destroy (ctx, client);
    zctx_destroy (&ctx);
    benchmark(initial_time, log_counter);
    //printf("<< EXIT >>\n");
    return 0;
}
