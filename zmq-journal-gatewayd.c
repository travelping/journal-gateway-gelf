
#include <assert.h>

#include "czmq.h"
#include "zmq.h"

static void *handler_routine (void *frames) {
    zctx_t *ctx = zctx_new ();
    void *query_handler = zsocket_new (ctx, ZMQ_DEALER);
    int rc = zsocket_connect (query_handler, "ipc://backend");
    assert(rc == 0);

    printf("<< THREAD INITIALISIERT >>\n");

    zframe_t *addr = * ((zframe_t **) frames);
    zframe_t *query = * (((zframe_t **) frames) + 1);

    printf("<< FRAMES INITIALISIERT >>\n");

    printf("<< QUERY = PING >>\n");
    zframe_t *response1 = zframe_new ("pong1", 6);
    zframe_t *response2 = zframe_new ("pong2", 6);
    zframe_t *response3 = zframe_new ("pong3", 6);
    printf("<< RESPONSE INITIALISIERT >>\n");
    zframe_send (&addr, query_handler, 1);
    printf("<< ERSTER FRAME GESENDET >>\n");
    zframe_send (&response1, query_handler, 1);
    zframe_send (&response2, query_handler, 1);
    zframe_send (&response3, query_handler, 0);
    printf("<< ZWEITER FRAME GESENDET >>\n");

    zframe_destroy (&query);
    printf("<< QUERY DESTROYED >>\n");
    zmq_close (query_handler);
    printf("<< SOCKET CLOSED >>\n");
    return NULL;
}

int main (void)
{
    void *ctx = zctx_new ();

    // Socket to talk to clients
    void *frontend = zsocket_new (ctx, ZMQ_ROUTER);
    assert(frontend);
    int rc = zsocket_bind (frontend, "tcp://*:5555");
    assert(rc == 5555);

    // Socket to talk to the query handlers
    void *backend = zsocket_new (ctx, ZMQ_ROUTER);
    assert(backend);
    rc = zsocket_bind (backend, "ipc://backend");
    assert(rc == 0);

    // Setup the poller for frontend and backend
    zmq_pollitem_t items[] = {
        {frontend, 0, ZMQ_POLLIN, 0},
        {backend, 0, ZMQ_POLLIN, 0},
    };

    while (1) {
        printf("<< POLLER WARTET >>\n");
        zmq_poll (items, 2, -1);
        printf("<< POLLER ÜBERSCHRITTEN >>\n");

        if (items[0].revents & ZMQ_POLLIN) {
            printf("<< FRONTEND >>\n");
            zframe_t *addr = zframe_recv (frontend);
            printf("<< ERSTER FRAME >>\n");
            zframe_t *query = zframe_recv (frontend);
            printf("<< ZWEITER FRAME >>\n");

            zframe_t* frames[2] = { addr , query };
            printf("<< FRAMES EINGELESEN >>\n");
            zthread_new (handler_routine, frames);
        }

        if (items[1].revents & ZMQ_POLLIN) {
            printf("<< BACKEND >>\n");
            zmsg_t *response = zmsg_new ();
            response = zmsg_recv (backend);
            zframe_t *own_addr = zmsg_pop (response);
            zframe_destroy (&own_addr);
            zmsg_send (&response, frontend);
            printf("<< RESPONSE GESENDET >>\n");
        }

    }

}

