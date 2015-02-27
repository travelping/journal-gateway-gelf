#include "czmq.h"
#include "zmq.h"
#include "jansson.h"
#include <getopt.h>

/* general options, fit them to your needs */
#define DEFAULT_FRONTEND_SOCKET "tcp://*:5555"  // used by the clients
#define BACKEND_SOCKET "ipc://backend"          // used by the query handlers
#define HANDLER_HEARTBEAT_INTERVAL 5*1000       // millisecs, defines the time interval in which the gateway will expect a heartbeat
#define GATEWAY_HWM 0                           // high water mark for the gateway
#define HANDLER_HWM 0                           // high water mark for the handlers
#define WAIT_TIMEOUT 60*60*1000*1000            // microsecs, how long to wait in 'follow mode' when there is no new log; 
                                                // must be at least HANDLER_HEARTBEAT_INTERVAL since the gateway is not able 
                                                // to answer heartbeats in time when not.
                                                // default: 1 hour


#define TARGET_ADDRESS_ENV "TARGET_ADDR"
#define REMOTE_JOURNAL_DIRECTORY "JOURNAL_DIR"

/* definitions for internal communication between gateway and client */
#define READY "\001"
#define END "\002"
#define HEARTBEAT "\003"
#define ERROR "\004"
#define TIMEOUT "\005"
#define STOP "\006"
#define LOGON "\007"
#define LOGOFF "\010"

#define HEARTBEATING 0                          // set to '1' if should always be active
// #define DEFAULT_CLIENT_SOCKET "tcp://localhost:5555"    // the socket the client should connect to
#define HEARTBEAT_INTERVAL 1000                 // msecs, this states after which time you send a heartbeat
#define SERVER_HEARTBEAT_INTERVAL 5000          // msecs, this states how much time you give the server to answer a heartbeat
#define CLIENT_HWM 0                            // high water mark for the clients

/* DEBUGGING, defines the time the gateway is waiting after sending one log */
#define SLEEP 0 // 1500000L //  500000000L

typedef struct RequestMeta {
    zframe_t *client_ID;
    char* client_ID_string;
    const char *format;
    int at_most;
    uint64_t since_timestamp;
    uint64_t until_timestamp;
    char *since_cursor;
    char *until_cursor;
    bool follow;
    bool listening;
    bool discrete;
    bool boot;
    char *field;

    void **clauses;         // array of clauses
    size_t n_clauses;

    bool reverse; 
}RequestMeta;

/* note: is destructed by RequestMeta */
typedef struct Clause {
    void **primitives;      // array of strings
    size_t n_primitives;    // number of boolean primitives
}Clause;

/* destructor for RequestMeta */
void RequestMeta_destruct (RequestMeta *args){
    free(args->client_ID_string);
    if (args->format != NULL) free( (void *) args->format);
    if (args->since_cursor != NULL) free(args->since_cursor);
    if (args->until_cursor != NULL) free(args->until_cursor);
    if (args->field != NULL ) free(args->field);
    void **clauses = args->clauses;
    if (clauses != NULL ){
        int i,j;
        for(i=0;i<args->n_clauses;i++){
            Clause *clause = clauses[i];
            for(j=0;j<clause->n_primitives;j++){
                free((clause->primitives)[j]);
            }
            free(clause->primitives);
            free(clause);
        }
        free(clauses);
    }
    free(args);
}

