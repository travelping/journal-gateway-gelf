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


/* a test client for zmq-journal-gatewayd */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <signal.h>

#include "zmq-journal-gatewayd.h"

static zctx_t *ctx;
static void *client;
uint64_t initial_time;
int log_counter = 0;

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

    /* initial setup */
    ctx = zctx_new ();
    client = zsocket_new (ctx, ZMQ_DEALER);
    zsocket_set_rcvhwm (client, CLIENT_HWM);
    zsocket_connect (client, CLIENT_SOCKET);

    /* for stopping the client and the gateway handler via keystroke (ctrl-c) */
    signal(SIGINT, stop_handler);

    /* send query */
    char *query_string = argv[1] != NULL ? argv[1] : QUERY_STRING;
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
        if( rc == 0 && HEARTBEATING ){
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
        if (zclock_time () >= heartbeat_at && HEARTBEATING) {
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
