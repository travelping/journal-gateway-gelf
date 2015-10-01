#define BACKEND_SOCKET "ipc://backend"          // used by the query handler

#define ENV_LOG_TARGET_SOCKET "JOURNAL_REMOTE_TARGET"
#define ENV_JOURNAL_SOURCE_DIRECTORY "JOURNAL_SOURCE_DIR"

#define DEFAULT_CTRL_EXPOSED_SOCKET "tcp://*:27002"
#define ENV_CTRL_EXPOSED_SOCKET "GATEWAY_CONTROL_PEER"

typedef struct RequestMeta {
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
    if (args->format != NULL) free( (void *) args->format);
    if (args->since_cursor != NULL) free(args->since_cursor);
    if (args->until_cursor != NULL) free(args->until_cursor);
    if (args->field != NULL ) free(args->field);
    void **clauses = args->clauses;
    if (clauses != NULL ){
        size_t i,j;
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
