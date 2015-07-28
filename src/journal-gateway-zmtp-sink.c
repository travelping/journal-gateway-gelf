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
#include "journal-gateway-zmtp-sink.h"
#include "journal-gateway-zmtp-control.h"

#define _GNU_SOURCE
#define KEYDATA(KEY) .key=KEY, .keylen=sizeof(KEY)

extern char *program_invocation_short_name;
static zctx_t *ctx;
static void *client, *router_control;
static bool active = true;
uint64_t initial_time;
long poll_wait_time = POLL_WAIT_TIME;

/* cli arguments */
int     reverse=0, follow=0, listening=1;
char    *since_timestamp=NULL, *until_timestamp=NULL, *client_socket_address=NULL, *control_socket_address=NULL,
        *format=NULL, *since_cursor=NULL, *until_cursor=NULL, *filter, *new_filter,
        *remote_journal_directory=NULL;

// constants
// cmd to get diskusage of all journalfiles
const char du_cmd_format[]  = "du -s %s";

typedef struct {
    char            *client_key;
    zframe_t        *id_frame;
    time_t          time_last_message;
    UT_hash_handle  hh; /*requirement for uthash*/
}Connection;

typedef struct {
    char            *src_machine_id;
    FILE            *sjr;
    UT_hash_handle  hh; /*requirement for uthash*/
}Logging_source_t;

// hash to note every incomming connection
Connection *connections = NULL;

// hash to note every outgoing log (differentiated by machine-id of the logging machine)
Logging_source_t *logging_sources = NULL;

typedef struct {
    char *cursor_start;
    char *cursor_end;
    char *realtime_start;
    char *realtime_end;
    char *monotonic_start;
    char *monotonic_end;

    char *machine_id_value;
    char *machine_id_end;
}Journalentry_fieldpins;

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
    SET_EXPOSED_PORT,
    SHOW_EXPOSED_PORT,
    SHOW_SOURCES,
    SET_LOG_DIRECTORY,
    SHOW_LOG_DIRECTORY,
    SHOW_DISKUSAGE,
    CTRL_SHUTDOWN,
} opcode;

struct Command{
    opcode id;
    const char *key;
    unsigned int keylen;
};

static struct Command valid_commands[] = {
    {.id = SHOW_HELP, KEYDATA("show_help")},
    {.id = HELP, KEYDATA("help")},
    {.id = FILTER_ADD, KEYDATA("filter_add")},
    {.id = FILTER_ADD_CONJUNCTION, KEYDATA("filter_add_conjunction")},
    {.id = FILTER_COMMIT, KEYDATA("filter_commit")},
    {.id = FILTER_FLUSH, KEYDATA("filter_flush")},
    {.id = FILTER_SHOW, KEYDATA("filter_show")},
    {.id = SHOW_FILTER, KEYDATA("show_filter")},
    {.id = SET_EXPOSED_PORT, KEYDATA("set_exposed_port")},
    {.id = SHOW_EXPOSED_PORT, KEYDATA("show_exposed_port")},
    {.id = SHOW_SOURCES, KEYDATA("show_sources")},
    {.id = SET_LOG_DIRECTORY, KEYDATA("set_log_directory")},
    {.id = SHOW_LOG_DIRECTORY, KEYDATA("show_log_directory")},
    {.id = SHOW_DISKUSAGE, KEYDATA("show_diskusage")},
    {.id = CTRL_SHUTDOWN, KEYDATA("shutdown")},
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
    free(item);
}

FILE* create_log_filestream(char *client_key){
    FILE *ret = NULL;

    // directoryname/machineid/
    const char directory_format[] = "%s/%s";
    // directoryname/machineid/machineid.journal
    const char sjr_cmd_format[] = "/lib/systemd/systemd-journal-remote -o %s/%s/%s.journal -";

    char *main_dir = remote_journal_directory;
    char *logorigin_dir = client_key;
    const char *jfile_name = "remote";

    size_t s = strlen(sjr_cmd_format) + strlen(main_dir) + strlen(logorigin_dir) + strlen(jfile_name);
    char *pathtojournalfile = (char*) malloc(s+1);
    assert (pathtojournalfile);
    sprintf (pathtojournalfile, sjr_cmd_format, main_dir, logorigin_dir, jfile_name);

    s = strlen(directory_format) + strlen(main_dir) + strlen(logorigin_dir);
    char *new_directory = (char*) malloc(s+1);
    assert(new_directory);
    sprintf(new_directory, directory_format, main_dir, logorigin_dir);
    int rc = mkdir(new_directory, 0766);
    if (rc == -1){
        switch(errno){
            case EEXIST:
                // directory already exists, everything's fine
                rc = 1;
                break;
            default:
                // some other error occured
                sd_journal_print(LOG_ERR, "error while creating the directory, errno: %d", errno);
        }
    }
    ret = popen(pathtojournalfile, "w");
    // if popen call failed
    if(ret == NULL){
        switch(errno){
            case EINVAL:
                sd_journal_print(LOG_ERR, "error while opening file stream to systemd-journal-remote: %s",
                    "type argument invalid");
                break;
            case EAGAIN:
                sd_journal_print(LOG_ERR, "error while opening file stream to systemd-journal-remote: %s",
                    "fork() cannot allocate sufficient memory OR the caller's RLIMIT_NPROC resource limit was encountered");
                break;
            case ENOMEM:
                sd_journal_print(LOG_ERR, "error while opening file stream to systemd-journal-remote: %s",
                    "fork() failed to allocate the necessary kernel structures because memory is tight");
                break;
            case ENOSYS:
                sd_journal_print(LOG_ERR, "error while opening file stream to systemd-journal-remote: %s",
                    "fork() is not supported on this platform");
                break;
            case EFAULT:
                sd_journal_print(LOG_ERR, "error while opening file stream to systemd-journal-remote: %s",
                    "pipefd is not valid");
                break;
            case EMFILE:
                sd_journal_print(LOG_ERR, "error while opening file stream to systemd-journal-remote: %s",
                    "too many file descriptors are in use by the process.");
                break;
            case ENFILE:
                sd_journal_print(LOG_ERR, "error while opening file stream to systemd-journal-remote: %s",
                    "the system limit on the total number of open files has been reached");
                break;
            default:
                sd_journal_print(LOG_ERR, "error while creating the directory, errno: %d", errno);
        }
    }

    free(pathtojournalfile);
    free(new_directory);
    return ret;
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

int get_timestamps(clockid_t clk_id, char *buf, size_t buf_len, size_t *ts_length){
    const uint64_t IN_MILLISECONDS  = 1000L;
    const uint64_t IN_SECONDS       = 1000L * IN_MILLISECONDS;
    struct timespec tp;
    int rc = clock_gettime(clk_id, &tp);
    if(rc == 0){
        uint64_t l_time = tp.tv_sec * IN_SECONDS + (tp.tv_nsec / 1000L);
        *ts_length = snprintf(buf, buf_len, "%llu", l_time );
    }
    return rc;
}

//helper for handling fields in journal
//the only information we're interested in are the value of the 3 systemd unique meta fields
//CURSOR, REALTIME_TIMESTAMP, MONOTONIC_TIMESTAMP (always the first 3, in this order)
//and the position and length of the meta field MACHINE_ID
//you can pass a valid pointer to 'equalsign' to signal
//that one of the 3 systemd unique meta fields is handled
//after execution 'equalsign' and 'end' point to the corresponding position in the string
//1: unexpected parsing error
//-1: in field _machine_id (done with pinpointing)
int pinpoint_metafields(const char* start, char** equalsign, char** end){
    int ret = 0;
    const char *machine_id_key = "_MACHINE_ID";
    char *akt_pos = (char*)start;       // casting to avoid compiler complaints

    // no systemd unique meta field
    if ( *equalsign == NULL ){
        // machine id field
        if ( strncmp(akt_pos, machine_id_key, sizeof(machine_id_key)) == 0 ){
            akt_pos += sizeof(machine_id_key);
            ret = -1;
        }
    }
    // search for '='  or '\n' as key-value separator (\n only appears with multi line values)
    while( akt_pos[0] != '=' && akt_pos[0] != '\n' ){
        akt_pos++;
    }
    if ( akt_pos[0] == '=' ){
        *equalsign=akt_pos;
        // '\n' marks the end of single line meta field
        while( akt_pos[0] != '\n' ){
            akt_pos++;
        }
    }
    else if ( akt_pos[0] == '\n'){
        akt_pos++;
        // multi line messages have their length encoded in the first entries after the key
        uint64_t value_offset = le64toh((uint64_t) *akt_pos);
        akt_pos += sizeof(uint64_t);
        *equalsign=akt_pos;
        akt_pos += value_offset;
    }
    *end=akt_pos;
    return ret;
}

/* retrieving positions of the 3 journal unique meta fields in the journal entry */
int pinpoint_all_metafields(const char *j_entry, Journalentry_fieldpins *pins){
    const char cursor[] = "__CURSOR";
    const char realtime[] = "__REALTIME_TIMESTAMP";
    const char monotonic[] = "__MONOTONIC_TIMESTAMP";
    //    start    equalsign   end
    char *s=NULL, *eq = NULL, *e = NULL;

    s = (char*) j_entry;

    eq = s + sizeof(cursor);
    pinpoint_metafields(s,&eq,&e);
    pins->cursor_start = s;
    pins->cursor_end   = e;

    s = e + 1;
    eq = s + sizeof(realtime);
    pinpoint_metafields(s,&eq,&e);
    pins->realtime_start = s;
    pins->realtime_end   = e;

    s = e + 1;
    eq = s + sizeof(monotonic);
    pinpoint_metafields(s,&eq,&e);
    pins->monotonic_start = s;
    pins->monotonic_end   = e;

    for(;pinpoint_metafields(s,&eq,&e)==0;s = e+1){
        eq = NULL;
    }
    pins->machine_id_value = eq + 1;
    pins->machine_id_end   = e;

    return 0;
}

/*
    converts input timestamp into format
*/
char* make_json_timestamp(char *timestamp){
    if (timestamp == NULL) {
        return NULL;
    }

    if (0 == strcmp("now", timestamp)) {
        char* json_timestamp = strdup("now");
        return json_timestamp;
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

void stop_gateway(int dummy) {
    UNUSED(dummy);
    sd_journal_print(LOG_INFO, "stopping the gateway sink...");
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

static void s_ignore_broken_pipe() {
    struct sigaction action;
    action.sa_handler = SIG_IGN;
    action.sa_flags = 0;
    sigemptyset (&action.sa_mask);
    sigaction(SIGPIPE, &action, NULL);
}

int wrapper_ls_hash_find_or_create(const char *machine_id, Logging_source_t **src){
    Logging_source_t *new_src;
    HASH_FIND_STR(logging_sources, machine_id, new_src);
    if (new_src == NULL){   // new machine id
        new_src = (Logging_source_t *) malloc( sizeof(Logging_source_t));
        assert(new_src);
        new_src->sjr = create_log_filestream(machine_id);
        assert(new_src->sjr);
        new_src->src_machine_id = machine_id;
        HASH_ADD_STR(logging_sources, src_machine_id, new_src);
    }
    *src = new_src;
    return 1;
}

int try_write(int fd, const void *buf, size_t count, char *machine_id){
    int rc = write(fd, buf, count);
    //every thing's fine
    if (rc >= 0) {
        return 1;
    }
    //something went wrong
    else{
        //stream is closed, reopen again
        if (errno==EBADF){
            sd_journal_print(LOG_ERR, "file stream for machine id %s was closed, reopening...", machine_id);
            Logging_source_t *src = NULL;
            wrapper_ls_hash_find_or_create(machine_id, &src);
            pclose(src->sjr);
            src->sjr = create_log_filestream(machine_id);
            //stream still closed due to some issues
            if(src->sjr == NULL){
                sd_journal_print(LOG_ERR, "reopening of file stream for machine id %s failed", machine_id);
                return 0;
            }
            sd_journal_print(LOG_INFO, "file stream for machine id %s was closed, reopened", machine_id);
            return -1;
        }
        else{
            sd_journal_print(LOG_ERR,
                "file stream for machine id %s has an issue, trying to close and open again", machine_id);
            Logging_source_t *src = NULL;
            wrapper_ls_hash_find_or_create(machine_id, &src);
            pclose(src->sjr);
            src->sjr = create_log_filestream(machine_id);
            //stream still closed due to some issues
            if(src->sjr == NULL){
                sd_journal_print(LOG_ERR, "reopening of file stream for machine id %s failed", machine_id);
                return 0;
            }
            sd_journal_print(LOG_INFO,
                "file stream for machine id %s had an issue, reopened", machine_id);
            return -1;
        }
    }
}

typedef struct{
    int fd;
    int ok;
    char *log_machine_id;
}whelper;

int whelper_write(whelper *h, const void *buf, size_t count){
    if (h->ok != 1){
        return 0;
    }
    h->ok = try_write(h->fd, buf, count, h->log_machine_id);
    return 1;
}

//writing the received journal entry in the corresponding journal file
//the location and name of the file depends on the value of the
//_MACHINE_ID meta field
int write_remote_log(void *frame_data, size_t frame_size){
    Logging_source_t *logging_source = NULL;
    whelper h;

    Journalentry_fieldpins pins;
    pinpoint_all_metafields(frame_data, &pins);
    h.log_machine_id = strndup(pins.machine_id_value, (pins.machine_id_end - pins.machine_id_value));
    wrapper_ls_hash_find_or_create(h.log_machine_id, &logging_source);
    h.fd = fileno(logging_source->sjr);
    h.ok = 1;

    const char realtime_prefix[]  = "__REALTIME_TIMESTAMP=";
    const char monotonic_prefix[] = "__MONOTONIC_TIMESTAMP=";
    const char orig_prefix[]      = "X";
    char timestamp_buffer[20];      // 20 = most chars an int64_t consumes in readable form
    size_t timestamp_buffer_end;

    //original cursor
    whelper_write(&h, pins.cursor_start, (pins.cursor_end - pins.cursor_start + 1));

    //host realtime timestamp
    get_timestamps(CLOCK_REALTIME, timestamp_buffer, sizeof(timestamp_buffer), &timestamp_buffer_end);
    whelper_write(&h, realtime_prefix, sizeof(realtime_prefix) -1);
    whelper_write(&h, timestamp_buffer, timestamp_buffer_end);
    whelper_write(&h, "\n", 1);

    //host monotonic timestamp
    get_timestamps(CLOCK_MONOTONIC, timestamp_buffer, sizeof(timestamp_buffer), &timestamp_buffer_end);
    whelper_write(&h, monotonic_prefix, sizeof(monotonic_prefix) -1);
    whelper_write(&h, timestamp_buffer, timestamp_buffer_end);
    whelper_write(&h, "\n", 1);

    // original body
    whelper_write(&h, pins.monotonic_end+1, frame_size-(pins.monotonic_end - pins.cursor_start + 1));

    // original timestamps with prefixes
    whelper_write(&h, orig_prefix, sizeof(orig_prefix) -1);
    whelper_write(&h, pins.realtime_start, (pins.realtime_end - pins.realtime_start + 1));
    whelper_write(&h, orig_prefix, sizeof(orig_prefix) -1);
    whelper_write(&h, pins.monotonic_start, (pins.monotonic_end - pins.monotonic_start + 1));

    // end of log
    whelper_write(&h, "\n", 1);

    if(h.ok!=1){
        return 0;
    }
    return 1;
}

/* Do something with the received (log)message */
int response_handler(zframe_t* cid, zmsg_t *response){
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
        }
        else if( memcmp( frame_data, LOGOFF, strlen(LOGOFF) ) == 0 ){
            sd_journal_print(LOG_INFO, "one source of the gateway logged off, ID: %s", client_ID);
            Connection *lookup = NULL;
            HASH_FIND_STR( connections, client_ID, lookup );
            con_hash_delete( &connections, lookup );
            ret=2;
        }
        // received a log message
        else if(((char*)frame_data)[0] == '_'){
            if(!write_remote_log(frame_data, frame_size)){
                sd_journal_print(LOG_ERR, "writing of log message to journal file failed");
                ret = -2;
            }
        }
        else{
            char *buf = malloc(frame_size+1);
            memcpy(buf, frame_data, frame_size);
            buf[frame_size] = NULL;
            sd_journal_send("PRIORITY=%i", LOG_NOTICE,
                            "MESSAGE=received unexpected frame: %s", buf,
                            "DUMP=%s", buf,
                            NULL);
            free(buf);
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

/* control API functions */

// returns a string with the help dialog
void show_help(char *ret){
    const char *msg =
        "You are talking with %s \n"
        "Valid commands are:\n"
        "\n"
        "       help                    will show this\n"
        "\n"
        "   Changing the log filters:\n"
        "   You need to set the desired filters and commit them afterwards\n"
        "       filter_add [FIELD]      requires input of the form VARIABLE=value\n"
        "                               successively added filters are ORed together\n"
        "       filter_add_conjunction  adds an AND to the list of filters, allowing to AND together the filters\n"
        "       filter_flush            drops all currently set filters\n"
        "       filter_show             shows the currently set filters\n"
        "       filter_commit           applies the currently set filters (all sources will only send corresponding messages)\n"
        "                               WARNING: this will set the same filter on EVERY source\n"
        "\n"
        "       set_exposed_port [PORT] requires a valid tcp port (default: tcp://127.0.0.1:5555)\n"
        "       show_exposed_port       shows the port on which the sink listens for incoming logs\n"
        "       show_sources            shows the connected sources (characterized as ZMQ connection-IDs)\n"
        "\n"
        "       set_log_directory [DIR] sets the directory in which the received logs will be stored\n"
        "       show_log_directory      show the directory in which the received logs are stored\n"
        "       show_diskusage          shows the used space of the selected directory (in bytes)\n"
        "\n"
        "       shutdown                stops this application\n"
        "\n\n";
    sprintf(ret, msg, program_invocation_short_name);
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
        sd_journal_print(LOG_ERR, "%s\n", "erroneus filter inserted, abbort");
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

/*
    returns the set filters in ret
*/
int filter_show(zframe_t **response){
    char *format_1 = "currently applied filter = %s\n";
    char *format_2 = "new filter (commit to apply) = %s\n";
    int length = strlen(format_1) + strlen(filter) + strlen(format_2) + strlen(new_filter);
    char *stringh = malloc(sizeof(char) * (length+1));
    length = sprintf(stringh,        format_1, filter);
             sprintf(stringh+length, format_2, new_filter);
    *response = zframe_new(stringh,strlen(stringh));
    free(stringh);
    return 1;
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

int filter_commit(zframe_t **response){
    free(filter);
    filter = strdup(new_filter);
    //waiting for source to finish old query
    sleep(1);
    send_stop();
    //waiting for source to finish this stop query
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
    char *stringh = "filter committed\n";
    *response = zframe_new(stringh,strlen(stringh));
    return 1;
}

/* changing the exposed port */
int set_exposed_port(int port, zframe_t **response){
    // check for valid port
    if(port <= 1023 || 65536 <= port){
        sd_journal_print(LOG_NOTICE, "%s", "attempt to set port to an invalid option");
        char *stringh = "port not set, please choose a valid one ( >1023, <65536 )\n";
        *response = zframe_new(stringh,strlen(stringh));
        return -1;
    }

    // actual change of the port
    int rc;
    rc = zsocket_unbind(client, client_socket_address);
    if(rc==-1){
    perror("zsocket_unbind");
    }
    assert ( rc==0 );
    sprintf(client_socket_address, "tcp://127.0.0.1:%d", port);
    rc = zsocket_bind(client, client_socket_address);
    assert( rc );
    sd_journal_print(LOG_INFO, "changed exposed port to %s", client_socket_address);

    char *stringh2 = "port changed\n";
    *response = zframe_new(stringh2,strlen(stringh2));

    return 0;
}

/* showing the exposed port */
int show_exposed_port(zframe_t **response){
    *response = zframe_new(client_socket_address,strlen(client_socket_address));
    return 1;
}

/* changing the directory, in which the remote journals are stored*/
int set_log_directory(char *new_directory, zframe_t **response){
    int ret = 1;

    // create specified directory with rwxrw-rw-
    ret = mkdir(new_directory, 0766);
    if (ret == -1){
        switch(errno){
            case EEXIST:
                // directory already exists, everything's fine
                ret = 1;
                break;
            default:
                // some other error occured
                char *stringh = "error while creating the directory\n";
                *response = zframe_new(stringh,strlen(stringh));
                return -1;
        }
    }
    free(remote_journal_directory);
    remote_journal_directory = new_directory;
    // adjust filestreams
    Logging_source_t *i, *tmp;
    HASH_ITER(hh, logging_sources, i, tmp){
        pclose(i->sjr);
        i->sjr = create_log_filestream(i->src_machine_id);
        //stream not open
        if(i->sjr == NULL){
            sd_journal_print(LOG_ERR, "opening of file stream for machine id %s failed", i->src_machine_id);
            char *stringh = "error while opening the file stream\n";
            *response = zframe_new(stringh,strlen(stringh));
            return -2;
        }
    }
    char *stringh = "directory set\n";
    *response = zframe_new(stringh,strlen(stringh));
    return ret;
}

int show_log_directory(zframe_t **response){
    *response = zframe_new(remote_journal_directory,strlen(remote_journal_directory));
    return 1;
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

// returns a string with the used space in bytes
void show_diskusage(char *ret){
    char du_cmd[2048];
    sprintf(du_cmd, du_cmd_format, remote_journal_directory);
    FILE* du = popen(du_cmd, "r");
    assert(du);
    char du_ret[2048];
    int rc = fscanf(du, "%s", du_ret);
    assert(rc);
    sprintf(ret, du_ret);
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
    creates response frame which has to be freed by the caller
*/
int execute_command(opcode command_id, json_t *command_arg, zframe_t **response){
    int port;
    char *dir, stringh[2048];

    switch (command_id){
        case FILTER_ADD:
            filter_add(get_arg_string(command_arg), response);
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
        case SET_EXPOSED_PORT:
            port = get_arg_int(command_arg);
            set_exposed_port(port, response);
            break;
        case SHOW_EXPOSED_PORT:
            show_exposed_port(response);
            break;
        case SET_LOG_DIRECTORY:
            dir = get_arg_string(command_arg);
            set_log_directory(dir, response);
            break;
        case SHOW_LOG_DIRECTORY:
            show_log_directory(response);
            break;
        case SHOW_SOURCES:
            show_sources(&stringh[0]);
            *response = zframe_new(stringh,strlen(stringh));
            break;
        case SHOW_HELP:
            show_help(&stringh[0]);
            *response = zframe_new(stringh,strlen(stringh));
            break;
        case HELP:
            show_help(&stringh[0]);
            *response = zframe_new(stringh,strlen(stringh));
            break;
        case SHOW_DISKUSAGE:
            show_diskusage(&stringh[0]);
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

#ifndef TEST
int main ( int argc, char *argv[] ){

    struct option longopts[] = {
        { "reverse",        no_argument,            &reverse,     1   },
        { "since",          required_argument,      NULL,         'b' },
        { "until",          required_argument,      NULL,         'c' },
        { "since_cursor",   required_argument,      NULL,         'd' },
        { "until_cursor",   required_argument,      NULL,         'e' },
        { "follow",         no_argument,            NULL,         'g' },
        { "help",           no_argument,            NULL,         'h' },
        { "filter",         required_argument,      NULL,         'i' },
        { 0, 0, 0, 0 }
    };

    int c;
    while((c = getopt_long(argc, argv, "a:b:c:d:e:f:ghs:", longopts, NULL)) != -1) {
        switch (c) {
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
            case 'h':
                fprintf(stdout,
"journal-gateway-zmtp-sink -- receiving logs from journal-gateway-zmtp-source over the network\n\n"
"Usage: journal-gateway-zmtp-sink   [--help] [--since] [--until]\n"
"                                   [--since_cursor] [--until_cursor]\n"
"                                   [--follow] [--reverse] [--filter]\n\n"
"   --help      will show this\n"
"   --since \trequires a timestamp with a format like \"2014-10-01 18:00:00\"\n"
"   --until \tsee --since\n"
"   --since_cursor \trequires a log cursor, see e.g. 'journalctl -o export'\n"
"   --until_cursor \tsee --since_cursor\n"
"\n"
"The sink is used to wait for incomming messages from journal-gateway-zmtp-source via an exposed socket.\n"
"Set this socket via the GATEWAY_LOG_PEER environment variable (must be usable by ZeroMQ).\n"
"Default is tcp://localhost:5555\n"
"\n"
"For further controls use the journal-gateway-zmtp-control tool\n"
"\n"
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

    remote_journal_directory = strdup_nullok(getenv(ENV_REMOTE_JOURNAL_DIRECTORY));
    if (!(remote_journal_directory)) {
        fprintf(stderr, "%s not specified.\n", ENV_REMOTE_JOURNAL_DIRECTORY);
        exit(1);
    }
    client_socket_address = strdup_nullok(getenv(ENV_LOG_EXPOSED_SOCKET));
    if (!(client_socket_address)) {
        fprintf(stderr, "%s not specified.\n", ENV_LOG_EXPOSED_SOCKET);
        exit(1);
    }
    control_socket_address = strdup_nullok(getenv(ENV_CTRL_EXPOSED_SOCKET));
    if (!(control_socket_address)){
        fprintf(stderr, "%s not specified, choosing the default (%s)\n",
            ENV_CTRL_EXPOSED_SOCKET, DEFAULT_CTRL_EXPOSED_SOCKET);
        control_socket_address = DEFAULT_CTRL_EXPOSED_SOCKET;
    }

    int major, minor, patch;
    zmq_version(&major, &minor, &patch);

    if(major<3){
        poll_wait_time *= ZMQ_VERSION_FACTOR;
    }

    printf("Uses ZMQ version %d.%d.%d\n", major, minor, patch);

    /* ensure existence of a machine id */
    check_machine_id();

    /* initialize filter */
    filter = strdup("[[]]");
    new_filter = strdup("[[]]");


    /* initial setup of connection  */
    ctx = zctx_new();
    client = zsocket_new (ctx, ZMQ_ROUTER);
    assert(client);
    //zsocket_set_rcvhwm (client, CLIENT_HWM);


    int rc;
    rc = zsocket_bind (client, client_socket_address);
    assert(rc);

    // setup of control connection
    router_control = zsocket_new(ctx, ZMQ_ROUTER);
    assert(router_control);
    rc = zsocket_bind (router_control, control_socket_address);
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

    // /* for stopping the gateway via keystroke (ctrl-c) */
    s_catch_signals();
    s_ignore_broken_pipe();

    /* receive controls or logs, initiate connections to new sources */
    while ( active ){
        rc=zmq_poll (items, 2, poll_wait_time);
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
                lookup->id_frame = zframe_dup(client_ID);
                lookup->client_key=strdup(client_key);
                HASH_ADD_STR(connections, client_key, lookup);
                sd_journal_print(LOG_INFO, "gateway has a new source, ID: %s", client_key);
            }
            free(client_key);
            lookup->time_last_message = get_clock_time();
            rc = response_handler(client_ID, response);
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

    sd_journal_print(LOG_INFO, "...gateway sink stopped");
    return 0;
}
#endif
