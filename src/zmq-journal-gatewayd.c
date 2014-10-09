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

/*
 * 'zmq-journal-gatewayd' is a logging gateway for systemd's journald. It 
 * extracts logs from the journal according to given conditions and sends them
 * to a client which requested the logs via a json-object. This object is sent
 * as a string. As transport ZeroMQ is used. Since the gateway works straight 
 * forward with ZeroMQ sockets you can in general choose how to communicate
 * between gateway and client in the way you can choose this for ZeroMQ sockets.
 *
 * A typical query string can look like
 *
 *  " { \"since_timestamp\" : \"2014-04-29T13:23:25Z\" , \"reverse\" : true } "
 *
 * The gateway would then send all logs since the given date until now. Logs are 
 * by default send by newest first, unless you activate the 'reverse' attribute.
 *
 * The gateway can work on (in theory) arbitrary many requests in parallel. The
 * message flow with a client follows the following specification:
 *
 * 1.   The client sends a query string which represents a (valid) json object.
 * 2.   the gateway sends a message ('READY') to acknowledge  the query as a first 
 *      response. 
 * 3.   After this initial response the gateway will start sending logs according
 *      to the given restrictions/conditions. Every log is sent in exactly one 
 *      zmq message. Possible restrictions/conditions can be seen in the 
 *      function definition of 'parse_json'.
 * 4.   If the query response was successful the gateway will close the request
 *      with an additional message ('END').
 *      If the query response was not (fully) successful the gateway will send 
 *      an error message ('ERROR').
 *      Another possibility regards a timeout due to heartbeating:
 * 5.   The gateway will always accept heartbeating messages ('HEARTBEAT') from
 *      a client but in general it is optional. Only if the follow functionality
 *      is used the gateway will expect a heartbeating by the client. If the 
 *      client misses a heartbeat the gateway will respond with a 'TIMEOUT'
 *      message and close the response stream. 
 * 6.   The client can stop the response stream of the gateway by sending a 'STOP' 
 *      message to the gateway. The gateway will respond with a 'STOP' message 
 *      and close the response stream.
 */

#include <stdio.h>
#include <string.h>
#include <alloca.h>
#include <assert.h>
#include <time.h>
#include <systemd/sd-journal.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>

#include "zmq-journal-gatewayd.h"

/* signal handler function, can be used to interrupt the gateway via keystroke */
static bool active = true;
void stop_gateway(int dummy) {
    sd_journal_print(LOG_INFO, "stopping the gateway...");
    active = false; // stop the gateway
}

typedef struct Connection {
    zframe_t *client_ID;
    zframe_t *handler_ID;
}Connection;

char *get_arg_string(json_t *json_args, char *key){
    json_t *json_string = json_object_get(json_args, key);
    if( json_string != NULL ){
        const char *string = json_string_value(json_string);
        char *string_cpy = (char *) malloc( sizeof(char) * (strlen(string)+1) );
        strcpy(string_cpy, string);
        return string_cpy;
    }
    else{
        return NULL;
    }
}

void set_matches(json_t *json_args, char *key, RequestMeta *args){
    json_t *json_array = json_object_get(json_args, key);
    if( json_array != NULL ){

        /*  
            The gateway accepets matches in form of boolean formulas.
            These formulas are represented in KNF such that every clause
            is represented as one array. The whole boolean formula is
            represented as an array of clauses/arrays. For example

            (PRIORITY=0 OR PRIORITY=1) AND (CODE_FILE=my_file)

            is represented through:
            
            [["PRIORITY=0", "PRIORITY=1"], ["CODE_FILE=my_file"]]
        */

        size_t n_clauses = json_array_size(json_array);                     // number of clauses 
        void **clauses = (void **) malloc( sizeof(Clause *) * n_clauses );  // array of clauses; the whole boolean formula

        size_t index;
        json_t *value;
        Clause *clause;
        json_array_foreach(json_array, index, value) {
            json_t *json_clause = json_array_get(json_array, index);
            clause = (Clause *) malloc( sizeof(Clause) );
            size_t n_primitives = json_array_size(json_clause);
            clause->primitives = (void **) malloc( sizeof(char *) * n_primitives );
            clause->n_primitives = n_primitives;

            size_t index1;
            json_t *value1;
            json_array_foreach(json_clause, index1, value1) {
                const char *json_clause_value = json_string_value(value1);
                (clause->primitives)[index1] = (char *) malloc( sizeof(char) * (strlen(json_clause_value)+1) );
                strcpy((clause->primitives)[index1], json_clause_value);
            }
            clauses[index] = clause;
        }

        args->n_clauses = n_clauses;
        args->clauses = clauses;

        return;
    }
    else{
        args->n_clauses = 0;
        args->clauses = NULL;
        return;
    }
}

bool get_arg_bool(json_t *json_args, char *key){
    json_t *json_boolean = json_object_get(json_args, key);
    if( json_boolean != NULL ){
        int boolean;
        json_unpack(json_boolean, "b", &boolean);
        return (boolean == 1) ? true : false;
    }
    else{
        return false;
    }
}

int get_arg_int(json_t *json_args, char *key){
    json_t *json_int = json_object_get(json_args, key);
    if( json_int != NULL ){
        int integer = json_number_value(json_int);
        return integer;
    }
    else
        return -1;
}

uint64_t get_arg_date(json_t *json_args, char *key){
    /* follows the human readable form "2012-04-23T18:25:43.511Z" */
    json_t *json_date = json_object_get(json_args, key);
    if( json_date != NULL ){
        const char *string = json_string_value(json_date);
        char string_cpy[strlen(string)+1];
        strcpy(string_cpy, string);

        /* decode the json date to unix epoch time, milliseconds are not considered */
        struct tm tm;
        time_t t;
        char *ptr = strtok(string_cpy, "T.");
        strptime(ptr, "%Y-%m-%d", &tm);
        ptr = strtok(NULL, "T.");
        strptime(ptr, "%H:%M:%S", &tm);
        tm.tm_isdst = -1;

        t = mktime(&tm) * 1000000;      // this time needs to be adjusted by 1000000 to fit the journal time

        return (uint64_t) t;
    }
    else{
        return -1;
    }
}

/* represents a connection between client and handler */
void Connection_destruct (void *_connection){
    Connection *connection = (Connection *) _connection;
    zframe_destroy( &(connection->handler_ID) );
    zframe_destroy ( &(connection->client_ID) );
    free( connection ) ;
}

/* fill a RequestMeta structure with the information from the query_string */
RequestMeta *parse_json(zmsg_t* query_msg){
    zframe_t *client_ID = zmsg_pop (query_msg);
    zframe_t *query_frame = zmsg_pop (query_msg);

    char *query_string = zframe_strdup (query_frame);
    zframe_destroy (&query_frame);
    json_error_t error;
    json_t *json_args = json_loads(query_string, 0, &error);
    free(query_string);

    /* invalid query */
    if (json_args == NULL)
        return NULL;

    /* fill args with arguments from json input */
    RequestMeta *args = malloc( sizeof(RequestMeta) );
    args->client_ID = client_ID;
    args->client_ID_string = zframe_strhex (client_ID);
    args->format = get_arg_string(json_args, "format");
    args->at_most = get_arg_int(json_args, "at_most");
    args->since_timestamp = get_arg_date(json_args, "since_timestamp");
    args->until_timestamp = get_arg_date(json_args, "until_timestamp");
    args->since_cursor = get_arg_string(json_args, "since_cursor");
    args->until_cursor = get_arg_string(json_args, "until_cursor");
    args->follow = get_arg_bool(json_args, "follow");
    args->discrete = get_arg_bool(json_args, "discrete");
    args->boot = get_arg_bool(json_args, "boot");
    args->field = get_arg_string(json_args, "field");
    set_matches(json_args, "field_matches", args); 
    args->reverse = get_arg_bool(json_args, "reverse");

    /* there are some dependencies between certain attributes, these can be set here */
    if ( args->until_cursor != NULL || (int) args->until_timestamp != -1 )
        args->follow = false;
    if ( args->follow == true )
        args->reverse = false;

    json_decref(json_args);
    return args;
}

/* some small helpers */
zmsg_t *build_msg_from_frame(zframe_t *ID, zframe_t *flag_frame){
    zmsg_t *msg = zmsg_new();
    zframe_t *ID_dup = zframe_dup (ID);
    zframe_t *flag_dup = zframe_dup (flag_frame);
    zmsg_push (msg, flag_dup);
    zmsg_push (msg, ID_dup);
    return msg;
}
zmsg_t *build_entry_msg(zframe_t *ID, char *entry_string, int entry_string_size){
    zmsg_t *msg = zmsg_new();
    zframe_t *entry_string_frame = zframe_new (entry_string, entry_string_size);
    zmsg_push (msg, entry_string_frame);
    zframe_t *ID_dup = zframe_dup (ID);
    zmsg_push (msg, ID_dup);
    return msg;
}
void send_flag( zframe_t *ID, void *socket, zctx_t *ctx, char *flag){
    zmsg_t *msg = zmsg_new();
    zframe_t *ID_dup = zframe_dup (ID);
    zframe_t *flag_frame = zframe_new ( flag, strlen(flag) + 1 );
    zmsg_push (msg, flag_frame);
    zmsg_push (msg, ID_dup);

    /* ID will not be destroyed! */
    zmsg_send (&msg, socket);

    /* context with all sockets will be destroyed if given */
    if( ctx != NULL )
        zctx_destroy (&ctx);
}

void adjust_journal(RequestMeta *args, sd_journal *j){
    /* initial position will be seeked, don't forget to 'next'  or 'previous' the journal pointer */
    if ( args->reverse == true && args->until_cursor != NULL)
        sd_journal_seek_cursor( j, args->until_cursor );
    else if ( args->reverse == false && args->since_cursor != NULL)
        sd_journal_seek_cursor( j, args->since_cursor );
    else if( args->reverse == true && (int) args->until_timestamp != -1)
        sd_journal_seek_realtime_usec( j, args->until_timestamp );
    else if ( args->reverse == false && (int) args->since_timestamp != -1)
        sd_journal_seek_realtime_usec( j, args->since_timestamp );
    else if (args->reverse == true)
        sd_journal_seek_tail( j );
    else if (args->reverse == false)
        sd_journal_seek_head( j );

    /* field matches conditions */
    int i,k;
    Clause *clause;
    for(i=0;i<args->n_clauses;i++){
        clause = (args->clauses)[i];
        for(k=0;k<clause->n_primitives;k++){
            sd_journal_add_match( j, clause->primitives[k], 0);
        }
        sd_journal_add_conjunction( j );
    }
}

int check_args(sd_journal *j, RequestMeta *args, uint64_t realtime_usec, uint64_t monotonic_usec){
    if( ( args->reverse == true && args->since_cursor != NULL && sd_journal_test_cursor ( j, args->since_cursor ) )
        || ( args->reverse == false && args->until_cursor != NULL && sd_journal_test_cursor ( j, args->until_cursor ) )
        || ( args->reverse == true && (int) args->since_timestamp != -1 && args->since_timestamp > realtime_usec )
        || ( args->reverse == false && (int) args->until_timestamp != -1 && args->until_timestamp < realtime_usec ) )
        return 1;
    else
        return 0;
}

char *get_entry_string(sd_journal *j, RequestMeta *args, char** entry_string, size_t* entry_string_size){

    const void *data;
    size_t length;
    size_t total_length = 0;
    int counter = 0, i;
    
    /* first get the number of fields to allocate memory */
    SD_JOURNAL_FOREACH_DATA(j, data, length)
        counter++;
    char *entry_fields[counter+1+3];        // +3 for meta information, prefixed by '__'
    int entry_fields_len[counter+1+3];        // +3 for meta information, prefixed by '__'

    /* then insert the meta information, memory allocation first */
    char *cursor;
    uint64_t realtime_usec;
    char realtime_usec_string[65];          // 64 bit +1 for \0
    uint64_t monotonic_usec;
    char monotonic_usec_string[65];         // 64 bit +1 for \0
    sd_id128_t boot_id;
    
    sd_journal_get_cursor( j, &cursor );    // needs to be free'd afterwards
    sd_journal_get_realtime_usec( j, &realtime_usec );
    sprintf ( realtime_usec_string, "%" PRId64 , realtime_usec );
    sd_journal_get_monotonic_usec( j, &monotonic_usec, &boot_id);
    sprintf ( monotonic_usec_string, "%" PRId64 , monotonic_usec );
    
    /* check against args if this entry should be sent */
    if (check_args( j, args, realtime_usec, monotonic_usec) == 1){
        free(cursor);
        *entry_string = END;
        *entry_string_size = strlen(END);
        return;
    }

    /* until now the prefixes for the meta information are missing */
    char *meta_information[] = { cursor, realtime_usec_string, monotonic_usec_string };
    const char *meta_prefixes[] = {"__CURSOR=", "__REALTIME_TIMESTAMP=" , "__MONOTONIC_TIMESTAMP=" };
    for(i=0; i<3; i++){
        int prefix_len = strlen(meta_prefixes[i]);
        int information_len = strlen(meta_information[i]);
        entry_fields[i] = (char *) alloca( sizeof(char) * ( prefix_len + information_len ));     
        memcpy ( entry_fields[i], (void *) meta_prefixes[i], prefix_len );
        memcpy ( entry_fields[i] + prefix_len, (void *) meta_information[i], information_len );
        entry_fields_len[i] = prefix_len + information_len;
        total_length += entry_fields_len[i];
    }
    free(cursor);

    /* then get all fields */
    counter = 3;
    SD_JOURNAL_FOREACH_DATA(j, data, length){
        entry_fields[counter] = (char *) alloca( sizeof(char) * (length) );
        memcpy (entry_fields[counter], (void *) data, length );
        entry_fields_len[counter] = length;
        total_length += length;

        /* check if this is a multiline message when export format (default) is chosen */
        if ((args->format == NULL || strcmp( args->format, "export" ) == 0) 
            && memchr(entry_fields[counter], '\n', length) != NULL)
        {
            char *field_name = strtok(entry_fields[counter], "=");
            int field_name_len = strlen(field_name);
            int new_length = length+8;  // +8 for 64 bit integer
            int64_t new_length64 = length - field_name_len - 1;

            entry_fields[counter] = (char *) alloca( sizeof(char) * new_length ); 
            memcpy (entry_fields[counter], (void *) field_name, field_name_len);
            *(entry_fields[counter] + field_name_len) = '\n';
            memcpy ( entry_fields[counter] + field_name_len + 1, (char *) &new_length64, 8 );
            memcpy ( entry_fields[counter] + field_name_len + 1 + 8, field_name + field_name_len + 1, length - field_name_len - 1 );

            entry_fields_len[counter] = new_length;
            total_length += 8;
        }
        counter++;
    }

    /* the data fields are merged together according to the given output format */
    if( args->format == NULL || strcmp( args->format, "export" ) == 0 || strcmp( args->format, "plain" ) == 0){  
        *entry_string = (char *) malloc( sizeof(char) * ( total_length + counter )); // counter times '\n'
        int p = 0;
        for(i=0; i<counter; i++){
            memcpy ( *entry_string + p, (void *) entry_fields[i], entry_fields_len[i] );
            p += entry_fields_len[i];
            *(*entry_string + p) = '\n';
            p++;
        }
        *entry_string_size = p;
    }
    else{
        *entry_string = ERROR;
        *entry_string_size = strlen(ERROR);
    }
    return;
}

/* for measuring performance of the gateway */
void benchmark( uint64_t initial_time, int log_counter ) {
    uint64_t current_time = zclock_time ();
    uint64_t time_diff_sec = (current_time - initial_time)/1000;
    uint64_t log_rate_sec = log_counter / time_diff_sec;
    /* use this only when you are certain not to produce floating point exceptions :D */
    //sd_journal_print(LOG_DEBUG, "sent %d logs in %d seconds ( %d logs/sec )\n", log_counter, time_diff_sec, log_rate_sec);
}

void send_flag_wrapper (sd_journal *j, RequestMeta *args, void *socket, zctx_t *ctx, const char *message, char *flag) {
    sd_journal_print(LOG_DEBUG, message);
    send_flag(args->client_ID, socket, ctx, flag);
    sd_journal_close( j );
    RequestMeta_destruct(args);
    return;
}

static void *handler_routine (void *_args) {
    RequestMeta *args = (RequestMeta *) _args;
    zctx_t *ctx = zctx_new ();
    void *query_handler = zsocket_new (ctx, ZMQ_DEALER);
    zsocket_set_sndhwm (query_handler, HANDLER_HWM);
    int rc = zsocket_connect (query_handler, BACKEND_SOCKET);

    /* send READY to the client */
    send_flag( args->client_ID, query_handler, NULL, READY );

    zmq_pollitem_t items [] = {
        { query_handler, 0, ZMQ_POLLIN, 0 },
    };

    /* DEBUGGING, can also be used to throttle the gateway down */
    struct timespec tim1, tim2;
    tim1.tv_sec  = 0;
    tim1.tv_nsec = SLEEP;

    /* create and adjust the journal pointer according to the information in args */
    sd_journal *j;
    sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
    adjust_journal(args, j);

    uint64_t heartbeat_at = zclock_time () + HANDLER_HEARTBEAT_INTERVAL;
    uint64_t initial_time = zclock_time ();
    int log_counter = 0;
    int loop_counter = args->at_most;

    while (loop_counter > 0 || args->at_most == -1) {

        loop_counter--;
        
        rc = zmq_poll (items, 1, 0);
        if( rc == -1 ){
            send_flag_wrapper (j, args, query_handler, ctx, "error in zmq poll", ERROR);
            return NULL;
        }

        if (items[0].revents & ZMQ_POLLIN){
            char *client_msg = zstr_recv (query_handler);
            if( strcmp(client_msg, HEARTBEAT) == 0 ){
                /* client sent heartbeat, only necessary when 'follow' is active */
                send_flag(args->client_ID, query_handler, NULL, HEARTBEAT);
                sd_journal_print(LOG_DEBUG, "received heartbeat, sending it back ...");
                heartbeat_at = zclock_time () + HANDLER_HEARTBEAT_INTERVAL;
            }
            else if( strcmp(client_msg, STOP) == 0 ){
                /* client wants no more logs */
                send_flag_wrapper (j, args, query_handler, ctx, "confirmed stop", STOP);
                free (client_msg);
                benchmark(initial_time, log_counter);
                return NULL;
            }
            free (client_msg);
        }

        /* timeout from client, only true when 'follow' is active and client does no heartbeating */
        if (zclock_time () >= heartbeat_at && args->follow) {
            send_flag_wrapper (j, args, query_handler, ctx, "Client Timeout", TIMEOUT);
            return NULL;
        }

        /* move forwards or backwards? default is backwards */
        if( args->reverse == false )
            rc = sd_journal_next(j);
        else
            rc = sd_journal_previous(j);

        /* try to send new entry if there is one */
        if( rc == 1 ){
            size_t entry_string_size;
            char *entry_string;
            get_entry_string( j, args, &entry_string, &entry_string_size ); 
            if ( memcmp(entry_string, END, strlen(END)) == 0 ){
                send_flag_wrapper (j, args, query_handler, ctx, "query finished successfully", END);
                benchmark(initial_time, log_counter);
                return NULL;
            }
            else if ( memcmp(entry_string, ERROR, strlen(ERROR)) == 0 ){
                send_flag(args->client_ID, query_handler, ctx, ERROR);
                sd_journal_close( j );
                RequestMeta_destruct(args);
                return NULL;
            }
            /* no problems with the new entry, send it */
            else{
                zmsg_t *entry_msg = build_entry_msg(args->client_ID, entry_string, entry_string_size);
                free (entry_string);
                zmsg_send (&entry_msg, query_handler);
                log_counter++;
            }
        }
        /* end of journal and 'follow' active? => wait some time */
        else if ( rc == 0 && args->follow ){
            sd_journal_wait( j, (uint64_t) WAIT_TIMEOUT );
        }
        /* in case moving the journal pointer around produced an error */
        else if ( rc < 0 ){
            send_flag_wrapper (j, args, query_handler, ctx, "journald API produced error", ERROR);
            return NULL;
        }
        /* query finished, send END and close the thread */
        else {
            send_flag_wrapper (j, args, query_handler, ctx, "query finished successfully", END);
            benchmark(initial_time, log_counter);
            return NULL;
        }

        /* debugging or throtteling */
        nanosleep(&tim1 , &tim2);
    }

    /* the at_most option can limit the amount of sent logs */
    send_flag_wrapper (j, args, query_handler, ctx, "query finished successfully", END);
    benchmark(initial_time, log_counter);
    return NULL;
}

int main (int argc, char *argv[]){

    struct option longopts[] = {
        { "socket",     required_argument,      NULL,         's' },
        { "help",       no_argument,            NULL,         'h' },
        { 0, 0, 0, 0 }
    };

    char *gateway_socket_address = NULL;

    int c;
    while((c = getopt_long(argc, argv, "s:", longopts, NULL)) != -1) {
        switch (c) {
            case 's':
                gateway_socket_address = optarg;
                break;
            case 'h':
                fprintf(stdout, 
"zmq-journal-gatewayd -- sending logs from systemd's journal over the network\n\
Usage: zmq-journal-gatewayd [--help] [--socket]\n\n\
\t--help \t\twill show this\n\
\t--socket \trequires a socket (must be usable by ZeroMQ), default is \"tcp://*:5555\"\n\n\
The zmq-journal-gatewayd-client can connect to the given socket.\n"
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

    sd_journal_print(LOG_INFO, "gateway started...");

    zctx_t *ctx = zctx_new ();

    // Socket to talk to clients
    void *frontend = zsocket_new (ctx, ZMQ_ROUTER);
    assert(frontend);
    zsocket_set_sndhwm (frontend, GATEWAY_HWM);
    zsocket_set_rcvhwm (frontend, GATEWAY_HWM);

    if(gateway_socket_address != NULL)
        zsocket_bind (frontend, gateway_socket_address);
    else
        zsocket_bind (frontend, DEFAULT_FRONTEND_SOCKET);

    // Socket to talk to the query handlers
    void *backend = zsocket_new (ctx, ZMQ_ROUTER);
    assert(backend);
    zsocket_set_sndhwm (backend, GATEWAY_HWM);
    zsocket_set_rcvhwm (backend, GATEWAY_HWM);
    zsocket_bind (backend, BACKEND_SOCKET);

    /* for stopping the gateway via keystroke (ctrl-c) */
    signal(SIGINT, stop_gateway);

    // Setup the poller for frontend and backend
    zmq_pollitem_t items[] = {
        {frontend, 0, ZMQ_POLLIN, 0},
        {backend, 0, ZMQ_POLLIN, 0},
    };

    zhash_t *connections = zhash_new ();
    Connection *lookup;
    zmsg_t *msg;
    RequestMeta *args; 
    while ( active ) {
        zmq_poll (items, 2, -1);

        if (items[0].revents & ZMQ_POLLIN) {
            msg = zmsg_recv (frontend);

            zframe_t *client_ID = zmsg_first (msg);

            char *client_ID_string = zframe_strhex (client_ID);
            lookup = (Connection *) zhash_lookup(connections, client_ID_string);

            /* first case: new query */
            if( lookup == NULL ){
                args = parse_json(msg);
                /* if query is valid open query handler and pass args to it */
                if (args != NULL){
                    Connection *new_connection = (Connection *) malloc( sizeof(Connection) );
                    new_connection->client_ID = client_ID;
                    new_connection->handler_ID = NULL;
                    zhash_update (connections, args->client_ID_string, new_connection);
                    zhash_freefn (connections, args->client_ID_string, Connection_destruct );
                    zthread_new (handler_routine, (void *) args);
                }
                /* if args was invalid answer with error */
                else{
                    sd_journal_print(LOG_INFO, "got invalid query");
                    send_flag( client_ID, frontend, NULL, ERROR );
                    zframe_destroy (&client_ID);
                }
            }
            /* second case: heartbeat or stop sent by client */
            else{
                zframe_t *client_msg_frame = zmsg_last (msg);
                zmsg_t *client_msg = build_msg_from_frame(lookup->handler_ID, client_msg_frame);
                zmsg_send (&client_msg, backend);
            }
            zmsg_destroy ( &msg );
            free(client_ID_string);
        }

        if (items[1].revents & ZMQ_POLLIN) {
            zmsg_t *response = zmsg_recv (backend);

            zframe_t *handler_ID = zmsg_pop (response);
            zframe_t *client_ID = zmsg_first (response);
            zframe_t *handler_response = zmsg_last (response);

            char *client_ID_string = zframe_strhex (client_ID);
            char *handler_response_string = zframe_strdup (handler_response);
            lookup = (Connection *) zhash_lookup(connections, client_ID_string);

            /* the handler ID is inserted in the connection struct when he answers the first time */
            if( lookup->handler_ID == NULL ){
                lookup->handler_ID = handler_ID;
            }
            else zframe_destroy (&handler_ID);

            /* case handler ENDs or STOPs the query, regulary or because of error (e.g. missing heartbeat) */
            if( strcmp( handler_response_string, END ) == 0 
                    || strcmp( handler_response_string, ERROR ) == 0 
                    || strcmp( handler_response_string, STOP ) == 0 
                    || strcmp( handler_response_string, TIMEOUT ) == 0){
                zhash_delete (connections, client_ID_string);
            }

            free(handler_response_string);
            free(client_ID_string);
            zmsg_send (&response, frontend);
        }
    }

    zhash_destroy (&connections);
    zctx_destroy (&ctx); 
    sd_journal_print(LOG_INFO, "...gateway stopped");
    return 0;

}
