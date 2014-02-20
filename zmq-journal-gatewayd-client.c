

#include "czmq.h"

int main(void)
{
    void *ctx = zctx_new ();
    void *client = zsocket_new (ctx, ZMQ_DEALER);
    zsocket_connect (client, "tcp://localhost:5555");

    char *string;
    zframe_t *frame;
    int more;

    zframe_t *query = zframe_new("ping", 5);
    zframe_send (&query, client, 0);

    zmsg_t *response = zmsg_new ();
    response = zmsg_recv(client);
    printf("=== RECEIVED ===\n");

    do{
        frame = zmsg_pop (response);
        more = zframe_more (frame);
        string = (char *) zframe_data (frame);
        printf("FRAME: %s\n", string);
        zframe_destroy (&frame);
    }while(more);

    zmsg_destroy (&response);

    return 0;
}
