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
 * 'journal-gateway-zmtp' is a logging gateway for systemd's journald. It
 * extracts logs from the journal according to given conditions and sends them
 * to a sink which requested the logs via a json-object. This object is sent
 * as a string. As transport ZeroMQ is used. Since the gateway works straight
 * forward with ZeroMQ sockets you can in general choose how to communicate
 * between source and sink in the way you can choose this for ZeroMQ sockets.
 *
 * A typical query string can look like
 *
 *  " { \"since_timestamp\" : \"2014-04-29T13:23:25Z\" , \"reverse\" : true } "
 *
 * The source would then send all logs since the given date until now. Logs are
 * by default send by newest first, unless you activate the 'reverse' attribute.
 *
 * The gateway can work on (in theory) arbitrary many requests in parallel. The
 * message flow with a sink follows the following specification:
 *
 * 0.   The source sends a message ('LOGON') to establish the connection.
 * 1.   The sink sends a query string which represents a (valid) json object.
 * 2.   the source sends a message ('READY') to acknowledge the query as a first
 *      response.
 * 3.   After this initial response the source will start sending logs according
 *      to the given restrictions/conditions. Every log is sent in exactly one
 *      zmq message. Possible restrictions/conditions can be seen in the
 *      function definition of 'parse_json'.
 * 4.   If the query response was successful the source will close the request
 *      with an additional message ('END').
 *      If the query response was not (fully) successful the source will send
 *      an error message ('ERROR').
 *      Another possibility regards a timeout due to heartbeating:
 * 5.   The source will always accept heartbeating messages ('HEARTBEAT') from
 *      a sink but in general it is optional. Only if the follow functionality
 *      is used the source will expect a heartbeating by the sink. If the
 *      sink misses a heartbeat the source will respond with a 'TIMEOUT'
 *      message and close the response stream.
 * 6.   The sink can stop the response stream of the source by sending a 'STOP'
 *      message to the source. The source will respond with a 'STOP' message
 *      and close the response stream.
 */

#include <stdio.h>
#include <string.h>
#include <alloca.h>
#include <assert.h>
#include <systemd/sd-journal.h>
#include <systemd/sd-id128.h>
#include <inttypes.h>
#define __USE_GNU 1
#include <time.h>
#include <signal.h>
#include <stdint.h>
#include <errno.h>
#include "journal-gateway-zmtp.h"
#include "journal-gateway-zmtp-control.h"
#include "journal-gateway-zmtp-source.h"

#define _GNU_SOURCE
#define KEYDATA(KEY) .key=KEY, .keylen=sizeof(KEY)

extern char *program_invocation_short_name;
static bool active = true, working_on_query = false;
void *frontend, *router_control;
char *source_journal_directory=NULL, *control_socket_address=NULL, *gateway_socket_address = NULL, *new_filter;
sd_journal *j = NULL;
RequestMeta *args = NULL;

// function declarations

void set_matches(json_t *json_args, char *key);
void adjust_journal();

/* signal handler function, can be used to interrupt the gateway via keystroke */
void stop_gateway(int dummy) {
    UNUSED(dummy);
    sd_journal_print(LOG_INFO, "stopping the gateway source...");
    active = false; // stop the gateway
}

static void s_catch_signals (){
    struct sigaction action;
    action.sa_handler = stop_gateway;
    action.sa_flags = 0;
    sigemptyset (&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
}

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

char* strdup_nullok(const char* inp){
    char *ret;
    if(!inp){
        ret = NULL;
    }
    else{
        ret = strdup(inp);
    }
    return ret;
}

// structures for controlhandling

typedef enum {
    SHOW_HELP = 1,
    HELP,
    FILTER_ADD,
    FILTER_ADD_CONJUNCTION,
    FILTER_COMMIT,
    FILTER_FLUSH,
    FILTER_SHOW,
    SHOW_FILTER,
    SET_TARGET_PORT,
    SHOW_TARGET_PORT,
    SET_LOG_DIRECTORY,
    SHOW_LOG_DIRECTORY,
    CTRL_SHUTDOWN,
} opcode;

struct Command{
    opcode id;
    const char *key;
    unsigned int keylen;
};

static struct Command valid_commands[] = {
    {.id = FILTER_ADD, KEYDATA("filter_add")},
    {.id = FILTER_ADD_CONJUNCTION, KEYDATA("filter_add_conjunction")},
    {.id = FILTER_COMMIT, KEYDATA("filter_commit")},
    {.id = FILTER_FLUSH, KEYDATA("filter_flush")},
    {.id = FILTER_SHOW, KEYDATA("filter_show")},
    {.id = SHOW_FILTER, KEYDATA("show_filter")},
    {.id = SET_TARGET_PORT, KEYDATA("set_target_port")},
    {.id = SHOW_TARGET_PORT, KEYDATA("show_target_port")},
    {.id = SHOW_HELP, KEYDATA("show_help")},
    {.id = HELP, KEYDATA("help")},
    {.id = SET_LOG_DIRECTORY, KEYDATA("set_log_directory")},
    {.id = SHOW_LOG_DIRECTORY, KEYDATA("show_log_directory")},
    {.id = CTRL_SHUTDOWN, KEYDATA("shutdown")},
};

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

int ctrl_send_c_to_backend(opcode c){
    zctx_t *ctx = zctx_new();
    void *backend = zsocket_new(ctx, ZMQ_DEALER);
    assert(backend);
    int rc;
    rc = zsocket_connect(backend, BACKEND_SOCKET);
    assert(rc == 0);
    zmsg_t *msg = zmsg_new();
    zframe_t *frame = zframe_new(&c, 1);
    zmsg_push(msg, frame);
    zmsg_send(&msg, backend);
    //cleanup
    sleep(1);
    zsocket_destroy(ctx, backend);
    zctx_destroy(&ctx);
    return 1;
}

/* control API */

/* changing the target peer */
int set_target_port(char *peer){
    int rc;
    rc = zsocket_disconnect(frontend, gateway_socket_address);
    if(rc==-1){
    perror("zsocket_disconnect");
    }
    assert ( rc==0 );
    sprintf(gateway_socket_address, "%s", peer);
    rc = zsocket_connect(frontend, gateway_socket_address);
    assert( rc==0 );
    sd_journal_print(LOG_INFO, "Changed target peer to %s", gateway_socket_address);

    return 1;
}

/* showing the exposed port */
int show_target_port(zframe_t **response){
    *response = zframe_new(gateway_socket_address,strlen(gateway_socket_address));
    return 1;
}

int show_help(char *ret){
    const char *msg =
        "You are talking with %s \n"
        "Valid commands are:\n"
        "\n"
        "       help                    will show this\n"
        "\n"
        "   Changing the logfilters:\n"
        "   You need to set the desired filters and commit them afterwards\n"
        "       filter_add [FIELD]      requires input of the form VARIABLE=value\n"
        "                               successively added filters are ORed together\n"
        "       filter_add_conjunction  adds an AND to the list of filters, allowing to AND together the filters\n"
        "       filter_flush            drops all currently set filters\n"
        "       filter_show             shows the currently set filters\n"
        "       filter_commit           applies the currently set filters\n"
        "\n"
        "       set_target_port [PORT] requires a valid tcp port (default: tcp://127.0.0.1:5555)\n"
        "       show_target_port       shows the port on which the sink listens for incomming logs\n"
        "\n"
        "       set_log_directory [DIR] sets the directory from which the logs will be read\n"
        "       show_log_directory      show the directory from which the logs are read\n"
        "\n"
        "       shutdown                stops this application\n"
        "\n\n";
    sprintf(ret, msg, program_invocation_short_name);
    return 1;
}

int filter_add(const char *filter_addition, zframe_t **response){
    char *filter_prefix, *filter_suffix;
    // drop the last 2 characters ']]'
    int length_new_filter = strlen(new_filter)-2;
    // new conjunction
    if(new_filter[length_new_filter-1] == '['){
        filter_prefix = "\"";
        filter_suffix = "\"]]";
    }
    // in "old" conjunction
    else if(new_filter[length_new_filter-1] == '"'){
        filter_prefix = ",\"";
        filter_suffix = "\"]]";
    }
    else{
        fprintf(stderr, "%s\n", "erroneus filter inserted, abbort");
        return 0;
    }
    int length_addition = strlen(filter_addition)+strlen(filter_prefix)+strlen(filter_suffix);
    size_t new_filter_size = sizeof(char) * (length_new_filter+length_addition+1);
    char *helper = malloc( new_filter_size );
    assert(helper);
    // length+1 because of trailing \0
    snprintf(helper, length_new_filter+1, new_filter);
    strcat(helper, filter_prefix);
    strcat(helper, filter_addition);
    strcat(helper, filter_suffix);
    free(new_filter);
    new_filter = helper;
    char *stringh = "filter added\n";
    *response = zframe_new(stringh,strlen(stringh));
    return 1;
}

int filter_add_conjunction(zframe_t **response){
    char *new_suffix = "],[]]";
    // drop the last 2 characters ']]'
    int length = strlen(new_filter)-2;
    size_t new_filter_size = sizeof(char) * (length+strlen(new_suffix)+1);
    char *helper = malloc( new_filter_size );
    assert(helper);
    // length+1 because of trailing \0
    snprintf(helper, length+1, new_filter);
    strcat(helper, new_suffix);
    free(new_filter);
    new_filter = helper;
    char *stringh = "conjunction added\n";
    *response = zframe_new(stringh,strlen(stringh));
    return 1;
}

int filter_flush(zframe_t **response){
    free(new_filter);
    new_filter=strdup("[[]]");
    char *stringh = "filter flushed\n";
    *response = zframe_new(stringh,strlen(stringh));
    return 1;
}

// returns the set filters which are packed in clauses in a human readable form
int string_from_clauses(char *ret, int *length){
    // if ret contains NULL pointer return the length of the result in length
    if (ret == NULL){
        *length = 0;
        size_t i,k;
        Clause *clause;
        for(i=0;i<args->n_clauses;i++){
            clause = (args->clauses)[i];
            if( i!=0 ){
                *length += strlen("AND ");
            }
            for(k=0;k<clause->n_primitives;k++){
                if( k!=0 ){
                    *length += strlen(" OR ");
                }
                *length += strlen((char*)clause->primitives[k]);
            }
            *length += strlen("\n");
        }
    }
    // otherwise return human readable form of the filter in ret and length in length
    else{
        *length = 0;
        size_t i,k;
        Clause *clause;
        for(i=0;i<args->n_clauses;i++){
            clause = (args->clauses)[i];
            if ( i!=0 ){
                *length += sprintf(ret+*length, "AND ");
            }
            for(k=0;k<clause->n_primitives;k++){
                if ( k!=0 ){
                    *length += sprintf(ret+*length, " OR ");
                }
                *length += sprintf(ret+*length, "%s",(char*)clause->primitives[k]);
            }
            *length += sprintf(ret+*length, "\n");
        }
    }
    return 1;
}

/*
    returns the set filters in a response frame
*/
int filter_show(zframe_t **response){
    char *format_1 = "currently applied filter = %s\n";
    int length_filter1;
    string_from_clauses(NULL, &length_filter1);
    char *filter = malloc(sizeof(char) * (length_filter1+1));
    string_from_clauses(filter, &length_filter1);
    char *format_2 = "new filter (commit to apply) = %s\n";
    int length_filter2 = strlen(format_1)-1 + strlen(filter) + strlen(format_2)-1 + strlen(new_filter);
    char *stringh = malloc(sizeof(char) * (length_filter2+1));

    length_filter2 =sprintf(stringh,        format_1, filter);
    sprintf(stringh+length_filter2, format_2, new_filter);
    *response = zframe_new(stringh,strlen(stringh));
    free(filter);
    free(stringh);
    return 1;
}

int filter_commit(zframe_t **response){
    json_t *json_helper = json_object();
    json_t *json_filter = json_loads(new_filter, JSON_REJECT_DUPLICATES, NULL);
    json_object_set(json_helper, "helper", json_filter);
    set_matches(json_helper, "helper");
    *response = zframe_new(CTRL_ACCEPTED,strlen(CTRL_ACCEPTED));
    json_decref(json_helper);
    char *stringh = "filter commited\n";
    ctrl_send_c_to_backend(FILTER_COMMIT);
    *response = zframe_new(stringh,strlen(stringh));
    return 1;
}

int show_filter(char *ret){
    int length = 0;
    length += sprintf(ret+length, "format=%s\n", args->format);
    length += sprintf(ret+length, "at_most=%d\n", args->at_most);
    length += sprintf(ret+length, "since_timestamp=%zu\n", args->since_timestamp);
    length += sprintf(ret+length, "until_timestamp=%zu\n", args->until_timestamp);
    length += sprintf(ret+length, "since_cursor=%s\n", args->since_cursor);
    length += sprintf(ret+length, "until_cursor=%s\n", args->until_cursor);
    length += sprintf(ret+length, "follow=%d\n", args->follow);
    length += sprintf(ret+length, "listening=%d\n", args->listening);
    length += sprintf(ret+length, "discrete=%d\n", args->discrete);
    length += sprintf(ret+length, "boot=%d\n", args->boot);
    length += sprintf(ret+length, "field=%s\n", args->field);
    length += sprintf(ret+length, "filter=\n");
    size_t i,k;
    Clause *clause;
    for(i=0;i<args->n_clauses;i++){
        clause = (args->clauses)[i];
        length += sprintf(ret+length, "    ");
        for(k=0;k<clause->n_primitives;k++){
            length += sprintf(ret+length, "%s ",(char*)clause->primitives[k]);
        }
        length += sprintf(ret+length, "\n");
    }

    return 1;
}

/* changing the directory, from which the journal entries are read */
int set_log_directory(const char *new_directory, zframe_t **response){

    // create specified directory with rwxrw-rw-
    int rc = mkdir(new_directory, 0766);
    if (rc == -1){
        switch(errno){
            case EEXIST:
                // directory already exists, everythings fine
                break;
            default:
                // some other error occured
                fprintf(stderr, "Error while creating the directory, errno: %d \n", errno);
                return -1;
        }
    }
    free(source_journal_directory);
    source_journal_directory = strdup(new_directory);
    // adjust the journal "stream"
    adjust_journal();

    char *stringh = "directory changed\n";
    *response = zframe_new(stringh,strlen(stringh));
    return 1;
}

int show_log_directory(zframe_t **response){
    *response = zframe_new(source_journal_directory,strlen(source_journal_directory));
    return 1;
}

// json helper

uint64_t get_timestamp_from_jstring(json_t *inp){
    const char *string = json_string_value(inp);
    char string_cpy[strlen(string)+1];
    strcpy(string_cpy, string);
    /* decode the json date to unix epoch time, milliseconds are not considered */
    struct tm tm;
    time_t t;
    char *ptr = strtok(string_cpy, "T.");
    strptime_l(ptr, "%Y-%m-%d", &tm, 0);
    ptr = strtok(NULL, "T.");
    strptime_l(ptr, "%H:%M:%S", &tm, 0);
    tm.tm_isdst = -1;

    t = mktime(&tm) * 1000000;      // this time needs to be adjusted by 1.000.000 to fit the journal time

    return (uint64_t) t;
}

char* get_string_from_jstring(json_t *arg){
    return strdup(json_string_value(arg));
}
int get_int_from_jstring(json_t *arg){
    int ret = 0;
    ret = atoi(json_string_value(arg));
    return ret;
}

int execute_command(opcode command_id, json_t *command_arg, zframe_t **response){
    char stringh[2048];

    switch (command_id){
        case FILTER_ADD:
            filter_add(get_string_from_jstring(command_arg), response);
            break;
        case FILTER_ADD_CONJUNCTION:
            filter_add_conjunction(response);
            break;
        case FILTER_FLUSH:
            filter_flush(response);
            break;
        case FILTER_COMMIT:
            filter_commit(response);
            break;
        case FILTER_SHOW:
            filter_show(response);
            break;
        case SHOW_FILTER:
            filter_show(response);
            break;
        case SET_TARGET_PORT: ;
            char *port = get_string_from_jstring(command_arg);
            set_target_port(port);
            *response = zframe_new(CTRL_ACCEPTED,strlen(CTRL_ACCEPTED));
            free(port);
            break;
        case SHOW_TARGET_PORT:
            show_target_port(response);
            break;
        case SET_LOG_DIRECTORY:
            set_log_directory(get_string_from_jstring(command_arg), response);
            break;
        case SHOW_LOG_DIRECTORY:
            show_log_directory(response);
            break;
        case HELP:
            show_help(&stringh[0]);
            *response = zframe_new(stringh,strlen(stringh));
            break;
        case SHOW_HELP:
            show_help(&stringh[0]);
            *response = zframe_new(stringh,strlen(stringh));
            break;
        case CTRL_SHUTDOWN:
            stop_gateway(0);
            *response = zframe_new(CTRL_ACCEPTED,strlen(CTRL_ACCEPTED));
            break;
        default:
            return 0;
    }
    return 1;
}

void set_matches(json_t *json_args, char *key){
    json_t *json_array = json_object_get(json_args, key);
    if( json_array != NULL ){

        /*
            The source accepts matches in form of boolean formulas.
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
        return get_timestamp_from_jstring(json_date);
    }
    else{
        return -1;
    }
    json_decref(json_date);
}

// apply the filter set in args to j
int apply_filter(){
    sd_journal_flush_matches( j );
    size_t i,k;
    Clause *clause;
    for(i=0;i<args->n_clauses;i++){
        clause = (args->clauses)[i];
        for(k=0;k<clause->n_primitives;k++){
            sd_journal_add_match( j, clause->primitives[k], 0);
        }
        sd_journal_add_conjunction( j );
    }
    return 1;
}

/* fill a RequestMeta structure with the information from the query_string */
RequestMeta *parse_json(zmsg_t* query_msg){
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
    args->format = get_arg_string(json_args, "format");
    args->at_most = get_arg_int(json_args, "at_most");
    //args->since_timestamp = get_arg_date(json_args, "since_timestamp");
    args->since_timestamp = 1000000 * time(NULL);
    args->until_timestamp = -1;
    args->since_cursor = get_arg_string(json_args, "since_cursor");
    args->until_cursor = get_arg_string(json_args, "until_cursor");
    args->follow = get_arg_bool(json_args, "follow");
    args->listening = get_arg_bool(json_args, "listen");
    args->discrete = get_arg_bool(json_args, "discrete");
    args->boot = get_arg_bool(json_args, "boot");
    args->field = get_arg_string(json_args, "field");
    set_matches(json_args, "field_matches");
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
zmsg_t *build_msg_from_frame(zframe_t *flag_frame){
    zmsg_t *msg = zmsg_new();
    zframe_t *flag_dup = zframe_dup (flag_frame);
    zmsg_push (msg, flag_dup);
    return msg;
}
zmsg_t *build_entry_msg(char *entry_string, int entry_string_size){
    zmsg_t *msg = zmsg_new();
    zframe_t *entry_string_frame = zframe_new (entry_string, entry_string_size);
    zmsg_push (msg, entry_string_frame);
    return msg;
}
void send_flag(void *socket, zctx_t *ctx, char *flag){
    zmsg_t *msg = zmsg_new();
    zframe_t *flag_frame = zframe_new ( flag, strlen(flag) + 1 );
    zmsg_push (msg, flag_frame);
    zmsg_send (&msg, socket);

    /* context with all sockets will be destroyed if given */
    if( ctx != NULL )
        zctx_destroy (&ctx);
}

void adjust_journal(){
    sd_journal_close( j );
    sd_journal_open_directory(&j, source_journal_directory, 0);
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
    sd_journal_flush_matches( j );
    size_t i,k;
    Clause *clause;
    for(i=0;i<args->n_clauses;i++){
        clause = (args->clauses)[i];
        for(k=0;k<clause->n_primitives;k++){
            sd_journal_add_match( j, clause->primitives[k], 0);
        }
        sd_journal_add_conjunction( j );
    }
}

int check_args(uint64_t realtime_usec, uint64_t monotonic_usec){
    UNUSED(monotonic_usec);
    if( ( args->reverse == true && args->since_cursor != NULL && sd_journal_test_cursor ( j, args->since_cursor ) )
        || ( args->reverse == false && args->until_cursor != NULL && sd_journal_test_cursor ( j, args->until_cursor ) )
        || ( args->reverse == true && (int) args->since_timestamp != -1 && args->since_timestamp > realtime_usec )
        || ( args->reverse == false && (int) args->until_timestamp != -1 && args->until_timestamp < realtime_usec ) )
        return 1;
    else
        return 0;
}

char *get_entry_string(char** entry_string, size_t* entry_string_size){

    const void *data;
    size_t length;
    size_t total_length = 0;
    int counter = 0, i;

    /* first get the number of fields to allocate memory */
    SD_JOURNAL_FOREACH_DATA(j, data, length)
        counter++;
    char *entry_fields[counter+1+3];        // +3 for meta information, prefixed by '__'
	//entry_fields[counter+3] = 0;  // guessing
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
    if (check_args(realtime_usec, monotonic_usec) == 1){
        free(cursor);
        *entry_string = END;
        *entry_string_size = strlen(END);
        return NULL;
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
            entry_fields[counter][field_name_len] = '\n';
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
		assert(entry_string);
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
    return NULL;
}

/* for measuring performance of the gateway */
#ifdef BENCHMARK
void benchmark( uint64_t initial_time, int log_counter ) {
    uint64_t current_time = zclock_time ();
    uint64_t time_diff_sec = (current_time - initial_time)/1000;
    uint64_t log_rate_sec = log_counter / time_diff_sec;
    /* use this only when you are certain not to produce floating point exceptions :D */
    //sd_journal_print(LOG_DEBUG, "sent %d logs in %d seconds ( %d logs/sec )\n", log_counter, time_diff_sec, log_rate_sec);
}
#endif

void send_flag_wrapper (void *socket, zctx_t *ctx, const char *message, char *flag) {
    sd_journal_print(LOG_DEBUG, message);
    send_flag(socket, ctx, flag);
    sd_journal_close( j );
    return;
}


static void *handler_routine (void *inp) {
    UNUSED(inp);
    zctx_t *ctx = zctx_new ();
    s_catch_signals();
    void *query_handler = zsocket_new (ctx, ZMQ_DEALER);
	assert(query_handler);
    //zsocket_set_sndhwm (query_handler, HANDLER_HWM);
    int rc = zsocket_bind (query_handler, BACKEND_SOCKET);

    /* send READY to the client */
    send_flag(query_handler, NULL, READY );

    zmq_pollitem_t items [] = {
        { query_handler, 0, ZMQ_POLLIN, 0 },
    };

    /* DEBUGGING, can also be used to throttle the gateway down */
    struct timespec tim1, tim2;
    tim1.tv_sec  = 0;
    tim1.tv_nsec = SLEEP;

    /* create and adjust the journal pointer according to the information in args */
    adjust_journal();

    int loop_counter = args->at_most;

    working_on_query = true;

    while (loop_counter > 0 || args->at_most == -1) {

        loop_counter--;

        rc = zmq_poll (items, 1, 0);
        if( rc == -1 ){
            send_flag_wrapper (query_handler, ctx, "error in zmq poll", ERROR);
            return NULL;
        }

        if (items[0].revents & ZMQ_POLLIN){
            char *client_msg = zstr_recv (query_handler);
            if( strcmp(client_msg, STOP) == 0 ){
                /* client wants no more logs */
                send_flag_wrapper (query_handler, ctx, "confirmed stop", STOP);
                free (client_msg);
                working_on_query = false;
                return NULL;
            }
            else if( client_msg[0] == FILTER_COMMIT ){
                apply_filter();
            }
            else{
                fprintf(stderr, "%s\n", "received unknown message");
            }
            free (client_msg);
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
            get_entry_string( &entry_string, &entry_string_size );
            if ( memcmp(entry_string, END, strlen(END)) == 0 ){
                send_flag_wrapper (query_handler, ctx, "query finished successfully", END);
                return NULL;
            }
            else if ( memcmp(entry_string, ERROR, strlen(ERROR)) == 0 ){
                send_flag(query_handler, ctx, ERROR);
                sd_journal_close( j );
                RequestMeta_destruct(args);
                return NULL;
            }
            /* no problems with the new entry, send it */
            else{
                zmsg_t *entry_msg = build_entry_msg(entry_string, entry_string_size);
                free (entry_string);
                zmsg_send (&entry_msg, query_handler);
            }
        }
        /* end of journal and 'follow' or 'listen' active? => wait indefinitely */
        else if ( rc == 0 && (args->follow || args->listening) ){
            sd_journal_wait( j, (uint64_t) 5000 );
        }
        /* in case moving the journal pointer around produced an error */
        else if ( rc < 0 ){
            send_flag_wrapper (query_handler, ctx, "journald API produced error", ERROR);
            return NULL;
        }
        /* query finished, send END and close the thread */
        else {
            send_flag_wrapper (query_handler, ctx, "query finished successfully", END);
            //benchmark(initial_time, log_counter);
            return NULL;
        }

        /* debugging or throtteling */
        nanosleep(&tim1 , &tim2);
    }

    /* the at_most option can limit the amount of sent logs */
    send_flag_wrapper (query_handler, ctx, "query finished successfully", END);
    //benchmark(initial_time, log_counter);
    return NULL;
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

int main (int argc, char *argv[]){

    struct option longopts[] = {
        { "help",       no_argument,            NULL,         'h' },
        { "version",    no_argument,            NULL,         'v' },
        { 0, 0, 0, 0 }
    };

    int c;
    while((c = getopt_long(argc, argv, "hv", longopts, NULL)) != -1) {
        switch (c) {
            case 'h':
                fprintf(stdout,
"journal-gateway-zmtp-source -- sending logs from systemd's journal over the network\n\
Usage: journal-gateway-zmtp-source [--help]\n\n\
\t--help \t\twill show this\n\n\
To set a socket to connect to a gateway sink set the JOURNAL_REMOTE_TARGET (must be usable by ZeroMQ)\n\
The journal-gateway-zmtp-sink has to expose the given socket.\n\n"
                );
                return 0;
            case 'v':
                fprintf(stdout, "Journal-Gateway-ZMTP Version %d.%d.%d\n", VMAYOR, VMINOR, VPATCH);
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

    source_journal_directory = strdup_nullok(getenv(ENV_JOURNAL_SOURCE_DIRECTORY));
    if (!(source_journal_directory)) {
        fprintf(stderr, "%s not specified.\n", ENV_JOURNAL_SOURCE_DIRECTORY);
        exit(1);
    }
    gateway_socket_address = strdup_nullok(getenv(ENV_LOG_TARGET_SOCKET));
    if (!gateway_socket_address) {
        fprintf(stderr, "%s not specified.\n", ENV_LOG_TARGET_SOCKET);
        exit(1);
    }
    control_socket_address = strdup_nullok(getenv(ENV_CTRL_EXPOSED_SOCKET));
    if (!(control_socket_address)){
        fprintf(stderr, "%s not specified, choosing the default (%s)\n",
            ENV_CTRL_EXPOSED_SOCKET, DEFAULT_CTRL_EXPOSED_SOCKET);
        control_socket_address = DEFAULT_CTRL_EXPOSED_SOCKET;
    }

    /* initialize filter */
    new_filter = strdup("[[]]");

    args = malloc( sizeof(RequestMeta) );
    json_t *json_helper = json_object();
    json_t *json_filter = json_loads("[[]]", JSON_REJECT_DUPLICATES, NULL);
    json_object_set(json_helper, "helper", json_filter);
    set_matches(json_helper, "helper");
    json_decref(json_helper);

    sd_journal_print(LOG_INFO, "gateway started...");

    int major, minor, patch;
    zmq_version(&major, &minor, &patch);

    printf("Uses ZMQ version %d.%d.%d\n", major, minor, patch);

    zctx_t *ctx = zctx_new ();


    int rc;
    // Socket to talk to clients
    frontend = zsocket_new (ctx, ZMQ_DEALER);
    assert(frontend);
    //zsocket_set_sndhwm (frontend, GATEWAY_HWM);
    //zsocket_set_rcvhwm (frontend, GATEWAY_HWM);

    rc = zsocket_connect (frontend, gateway_socket_address);
    assert(rc == 0);

    // Socket to talk to the query handlers
    void *backend = zsocket_new (ctx, ZMQ_ROUTER);
    assert(backend);
    //zsocket_set_sndhwm (backend, GATEWAY_HWM);
    //zsocket_set_rcvhwm (backend, GATEWAY_HWM);
    rc = zsocket_connect (backend, BACKEND_SOCKET);
    assert(rc == 0);

    router_control = zsocket_new(ctx, ZMQ_ROUTER);
    assert(router_control);
    rc = zsocket_bind (router_control, control_socket_address);
    assert(rc);

    // Setup the poller for frontend, backend and controls
    zmq_pollitem_t items[] = {
        {frontend, 0, ZMQ_POLLIN, 0},
        {backend, 0, ZMQ_POLLIN, 0},
        {router_control, 0, ZMQ_POLLIN, 0},
    };
    /* initiate connection to the sink */
    send_flag(frontend, NULL, LOGON );


    zmsg_t *msg, *response;
    zframe_t *handler_ID = NULL, *client_ID;

    // /* for stopping the gateway via keystroke (ctrl-c) */
    s_catch_signals();
    while ( active ) {
        rc=zmq_poll (items, 3, 60000);

        // polled unexpected item or got interupted:
        if ( rc==-1 ){
            switch(errno){
                // poll received a signal
                case EINTR:
                    stop_gateway(0);
                    break;
                default: sd_journal_print(LOG_INFO, "Faulty message received");
            }
        }

        // received a message from the sink
        if (items[0].revents & ZMQ_POLLIN) {
            msg = zmsg_recv (frontend);

            // expecting query
            if(!working_on_query){
                args = parse_json(msg);
                /* if query is valid open query handler and pass args to it */
                if (args != NULL) {
                    zthread_new (handler_routine, 0);
                }
                /* if args was invalid answer with error */
                else {
                    sd_journal_print(LOG_INFO, "got invalid query");
                    send_flag(frontend, NULL, ERROR );
                }
            zmsg_destroy ( &msg );
            }
            // working on query, expecting notification (STOP, END, ...)
            else{
                zframe_t *hid_dup = zframe_dup(handler_ID);
                zmsg_push(msg, hid_dup);
                zmsg_send(&msg, backend);
            }
        }

        // received a message from the query handler
        if (items[1].revents & ZMQ_POLLIN) {
            response = zmsg_recv (backend);

            handler_ID = zmsg_pop (response);
            zframe_t *handler_response = zmsg_last (response);

            char *handler_response_string = zframe_strdup (handler_response);

            /* case handler ENDs or STOPs the query, regulary or because of error (e.g. missing heartbeat) */
            if( strcmp( handler_response_string, END ) == 0
                    || strcmp( handler_response_string, ERROR ) == 0
                    || strcmp( handler_response_string, STOP ) == 0
                    || strcmp( handler_response_string, TIMEOUT ) == 0){
            }

            free(handler_response_string);
            zmsg_send (&response, frontend);
        }
        /* receive controls */
        if(items[2].revents & ZMQ_POLLIN){
            response = zmsg_recv(router_control);
            client_ID = zmsg_pop (response);
            assert(client_ID);
            rc = control_handler(response, client_ID);
            assert(rc);
            zmsg_destroy (&response);
        }
    }
    /*telling the sink that this source is shutting down*/
    send_flag(frontend, NULL, LOGOFF);

    zctx_destroy (&ctx);
    sd_journal_print(LOG_INFO, "...gateway source stopped");
    return 0;
}
