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
#include <alloca.h>
#include <assert.h>
#include <systemd/sd-journal.h>
#include <systemd/sd-id128.h>
#include <inttypes.h>
#include <time.h>
#include <signal.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include "journal-gateway-gelf.h"

#define _GNU_SOURCE
#define KEYDATA(KEY) .key=KEY, .keylen=sizeof(KEY)
#define DEFAULT_PRIO 6

extern char *program_invocation_short_name;
static bool active = true;
void *frontend, *router_control;
char *source_journal_directory=NULL, *control_socket_address=NULL, *gateway_socket_address = NULL, *filter;
sd_journal *j = NULL;

/* arguments for 'filtering' */
uint64_t since_timestamp;
uint64_t until_timestamp;

/* signal handler function, can be used to interrupt the gateway via keystroke */
void stop_gateway(int dummy) {
    UNUSED(dummy);
    sd_journal_print(LOG_INFO, "stopping the gateway...");
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

/*
   this doesnt exactly resemble what it is named after:
   you can't change the base or retrieve and endptr
   but it is sufficient for our usecase
*/
long int strtol_nullok(const char* inp){
    long int ret;
    if(!inp){
        ret = -1;
    }
    else{
        ret = strtol(inp, NULL, 10);
    }
    return ret;
}

// json helper

int64_t get_timestamp_from_jstring(const json_t *inp){
    const char *string = json_string_value(inp);
    /* decode the json date to unix epoch time, milliseconds are not considered */
    struct tm tm;
    time_t t;
    strptime(string, "%Y-%m-%dT%H:%M:%S", &tm);
    tm.tm_isdst = -1;

    t = mktime(&tm) * 1000000;      // this time needs to be adjusted by 1.000.000 to fit the journal time

    return (int64_t) t; // int64 is still big enough (by 4 levels of magnitude)
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

int64_t get_arg_date(json_t *json_args, char *key){
    /* follows the human readable form "2012-04-23T18:25:43.511Z" */
    json_t *json_date = json_object_get(json_args, key);
    if( json_date != NULL ){
        int64_t r = get_timestamp_from_jstring(json_date);
        json_decref(json_date);
        return r;
    }
    return -1;
}

//TODO: introduce https support (ssl handshake etc.)
int send_to_http (CURL *curl, const char *payload) {

    CURLcode rc;

    if(curl) {
        /* First set the URL that is about to receive our POST. This URL can
           just as well be a https:// URL if that is what should receive the
        data. */
        curl_easy_setopt(curl, CURLOPT_POST, CURLOPT_POSTFIELDS);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
        rc = curl_easy_perform(curl);

        /* Check for errors */
        if(rc != CURLE_OK){
            sd_journal_print(LOG_ERR, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(rc));
            /*
            wait for a short time to not create a feedback loop with journal entries
            we're not able to send
            */
            sleep(5);
        }
    /* always cleanup */

    }
    else rc = -1;
    return rc;
}

int check_timestamps(){
    uint64_t realtime_usec, monotonic_usec;
    sd_id128_t boot_id;
    int rc;

    rc = sd_journal_get_realtime_usec( j, &realtime_usec );
    assert(rc == 0);
    rc = sd_journal_get_monotonic_usec( j, &monotonic_usec, &boot_id);
    assert(rc == 0);
    // check whether since_timestamp <= realtime_usec <= until_timestamp
    if( ( (int) until_timestamp == -1 || realtime_usec <= until_timestamp )
        && ( (int) since_timestamp == -1 || since_timestamp <= realtime_usec ) )
        return 1;
    else
        return 0;
}

void adjust_journal(){
    sd_journal_close( j );
    sd_journal_open_directory(&j, source_journal_directory, 0);
    /* set inital position of the journal */
    if ( (int) since_timestamp != -1)
        sd_journal_seek_realtime_usec( j, since_timestamp );
    else
        sd_journal_seek_tail( j );
}

// returns allocated copy of value
static char *get_value(const void *data, size_t length) {
    char *sep = strchr(data, '=');
    if (!sep) return NULL;
    size_t valsize = length - (sep - (char*)data + 1) + 1; // excluding '=', including '\0'
    char *ret = malloc(valsize);
    assert(ret);
    memcpy(ret, sep+1, valsize-1);
    ret[valsize-1] = 0;
    return ret;
}

// returns allocated copy of key
static char *get_key(const void *data) {
    char *sep = strchr(data, '=');
    if (!sep) return NULL;
    size_t keysize = (sep - (char*)data) + 2; // including prepended '_', including '\0'
    char *ret = malloc(keysize);
    assert(ret);
    ret[0] = '_';
    memcpy(ret+1, data, keysize-2);
    ret[keysize-1] = 0;
    return ret;
}

// returns 0 on sucess, json_entry_string has to be free'd by the caller
int *get_entry_string(char** json_entry_string){
    const void *data;
    json_t *message = json_object();
    assert(message);
    size_t length;

    // journal meta information, prefixed by '__'
    char *cursor;
    uint64_t realtime_usec;
    uint64_t monotonic_usec;
    sd_id128_t boot_id;

    /* mapping from systemd- to GELF- field names */
    const char *fn_sd_host="_HOSTNAME", *fn_gelf_host="host";
    const char *fn_sd_msg="MESSAGE",    *fn_gelf_msg="short_message";
    const char /**fn_sd_time="__REALTIME_TIMESTAMP",*/ *fn_gelf_time="timestamp";
    const char *fn_sd_prio="PRIORITY",  *fn_gelf_prio="level";

    int rc = 0;

    //add version field necessary for GELF
    rc = json_object_set_new(message, "version", json_string("1.1"));
    assert(rc == 0);

    /* get data necessary for GELF*/

    rc = sd_journal_get_data(j, fn_sd_host, &data, &length);
    if (!rc){
        char *v = get_value(data, length);
        assert(v);
        rc = json_object_set_new(message, fn_gelf_host, json_string(v));
        assert(rc == 0);
        free(v);
    }
    else{
        rc = json_object_set_new(message, fn_gelf_host, json_string("not_available"));
        assert(rc == 0);
    }
    rc = sd_journal_get_data(j, fn_sd_msg, &data, &length);
    if (!rc){
        char *v = get_value(data, length);
        assert(v);
        rc = json_object_set_new(message, fn_gelf_msg, json_string(v));
        assert(rc == 0);
        free(v);
    }
    else{
        rc = json_object_set_new(message, fn_gelf_msg, json_string("not_available"));
        assert(rc == 0);
    }
    rc = sd_journal_get_data(j, fn_sd_prio, &data, &length);
    if (!rc){
        char *v = get_value(data, length);
        assert(v);
        int prio = strtol(v, NULL, 10);
        if (prio<0){
            prio = 0;
            sd_journal_print(LOG_ERR, "Received PRIORITY below 0");
        }
        if (prio>7){
            prio = 7;
            sd_journal_print(LOG_ERR, "Received PRIORITY above 7");
        }
        rc = json_object_set_new(message, fn_gelf_prio, json_integer(prio));
        assert(rc == 0);
        free(v);
    }
    else{
        rc = json_object_set_new(message, fn_gelf_prio, json_integer(DEFAULT_PRIO));
        assert(rc == 0);
    }

    // get systemd journal meta fields cursor, realtime- and monotonic timestamp
    // __REALTIME_TIMESTAMP corresponds to  GELF necessary timestamp
    const char *meta_prefixes[] = {"___CURSOR", fn_gelf_time , "___MONOTONIC_TIMESTAMP" };
    rc = sd_journal_get_cursor( j, &cursor );    // needs to be free'd afterwards
    assert(rc == 0);
    rc = json_object_set_new(message, meta_prefixes[0], json_string(cursor));
    assert(rc == 0);
    free(cursor);

    rc = sd_journal_get_realtime_usec( j, &realtime_usec );
    assert(rc == 0);
    //adjust time from microseconds (systemd) to seconds (GELF) since unix epoch
    realtime_usec /= 1000000;
    rc = json_object_set_new(message, meta_prefixes[1], json_integer(realtime_usec));
    assert(rc == 0);

    rc = sd_journal_get_monotonic_usec( j, &monotonic_usec, &boot_id);
    assert(rc == 0);
    rc = json_object_set_new(message, meta_prefixes[2], json_integer(monotonic_usec));
    assert(rc == 0);

    /* get all remaining fields */
    // (PRIORITY, _HOSTNAME, and MESSAGE are read again)

    // format of prefixes: additional '_' for additional fields in GELF
    // format of retrieved arguments: data="FIELD_NAME=field_value" length=
    SD_JOURNAL_FOREACH_DATA(j, data, length){
        char *v = get_value(data, length);
        assert(v);
        char *k = get_key(data);
        assert(k);
        rc = json_object_set_new(message, k, json_string(v));
        assert(rc == 0);
        free(v);
        free(k);
    }

    *json_entry_string = json_dumps(message, JSON_ENSURE_ASCII);
    json_decref(message);
    return 0;
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

static void *handler_routine () {
    s_catch_signals();

    /* DEBUGGING, can also be used to throttle the gateway down */
    struct timespec tim1, tim2;
    tim1.tv_sec  = 0;
    tim1.tv_nsec = SLEEP;

    /* create and adjust the journal pointer according to the information in args */
    adjust_journal();

    /* In windows, this will init the winsock stuff */
    curl_global_init(CURL_GLOBAL_ALL);

    /* Setup curl handle as input for the libcurl interface */
    CURL *curl;
    curl = curl_easy_init();
    assert(curl);

    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "journal-gateway-gelf/1.0");
    curl_easy_setopt(curl, CURLOPT_URL, gateway_socket_address);

    int rc;

    while (active) {


        bool valid_entry = true;
        /* iterate over entries, until
           * the next valid one for our configuration is found OR
           * the end of the journal is reached
           this respects:
           * timestamp
           TODO:
           * boot-id
           * filter (logical field combinations)
           * cursor
        */
        do {
            rc = sd_journal_next(j);
            valid_entry = check_timestamps();
        }while(!valid_entry && rc != 0);

        /* try to send new entry if there is one */
        if( rc == 1 ){
            char *json_entry_string;
            get_entry_string( &json_entry_string ); // json_entry_string has to be free'd
            send_to_http(curl, json_entry_string);
            free(json_entry_string);
        }
        /* end of journal ? => wait indefinitely */
        else if ( rc == 0 ){
            sd_journal_wait( j, (uint64_t) -1 );
        }
        /* in case moving the journal pointer around produced an error */
        else if ( rc < 0 ){
            sd_journal_print(LOG_ERR, "journald API produced error");
            sd_journal_close( j );
            return NULL;
        }
        /* query finished, send END and close the thread */
        else {
            sd_journal_print(LOG_DEBUG, "query finished successfully1");
            sd_journal_close( j );
            //benchmark(initial_time, log_counter);
            return NULL;
        }

        /* debugging or throtteling */
        nanosleep(&tim1 , &tim2);
    }
    // cleanup
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    sd_journal_print(LOG_DEBUG, "reading from journal finished");
    sd_journal_close( j );
    //benchmark(initial_time, log_counter);
    return NULL;
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
"journal-gateway-gelf -- sending logs from systemd's journal over the network\n\
Usage: journal-gateway-gelf [--help]\n\n\
\t--help \t\twill show this\n\n\
To set a socket to connect to a graylog2 server set the JOURNAL_GELF_REMOTE_TARGET\n\
\n"
                );
                return 0;
            case 'v':
                fprintf(stdout, "Journal-Gateway-GELF Version %d.%d.%d\n", VMAYOR, VMINOR, VPATCH);
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
    if (strncmp("http://", gateway_socket_address, 7)) {
        sd_journal_print(LOG_ERR, "unsupported URL-scheme for %s configured", ENV_LOG_TARGET_SOCKET);
        exit(1);
    }
    since_timestamp = strtol_nullok(getenv(ENV_SINCE_TIMESTAMP));
    until_timestamp = strtol_nullok(getenv(ENV_UNTIL_TIMESTAMP));

    json_t *json_helper = json_object();
    json_t *json_filter = json_loads("[[]]", JSON_REJECT_DUPLICATES, NULL);
    json_object_set_new(json_helper, "helper", json_filter);
    json_decref(json_helper);

    sd_journal_print(LOG_INFO, "gateway started...");

    // /* for stopping the gateway via keystroke (ctrl-c) */
    s_catch_signals();

    handler_routine();
    //cleanup
    free(source_journal_directory);
    free(gateway_socket_address);

    sd_journal_print(LOG_INFO, "...gateway stopped");
    return 0;
}
