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
#include <sys/stat.h>
#include <errno.h>

#include "journal-gateway-zmtp.h"
#include "journal-gateway-zmtp-control.h"



void stop_handler(int dummy) {
    UNUSED(dummy);
}

static void s_catch_signals (){
    struct sigaction action;
    action.sa_handler = stop_handler;
    action.sa_flags = 0;
    sigemptyset (&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
}

int parse_command(char **command, char **argument){
    char inp[1024];

    //get the input, checking NULL to catch EOF input
    if(fgets(inp, sizeof(inp), stdin) == NULL){
        *command = strdup("");
        *argument = strdup("");
        return 0;
    }

    // parse the input
    // leading spaces
    size_t i=0;
    while(isspace(inp[i])&& i<sizeof(inp)){
        i++;
    }
    // command
    size_t pc = i, lc = 0;
    while(!isspace(inp[i]) &&  i<sizeof(inp)){
        lc++;
        i++;
    }
    // spaces between command and argument
    while(isspace(inp[i]) && i<sizeof(inp)){
        i++;
    }
    // argument
    size_t pa=i, la=0;
    while(inp[i]!='\n' && inp[i]!=EOF && i<sizeof(inp)){
        la++;
        i++;
    }

    *command = strndup(inp+pc, lc);
    *argument = strndup(inp+pa, la);

    return 1;
}

int send_command(void *socket, char *command, char *argument){
    zmsg_t *msg = zmsg_new();
    assert(msg);
    json_t *package = json_object();
    assert(package);
    int rc = json_object_set(package, command, json_string(argument));
    // check if creation of the package was succesful
    if(rc!=0){
        fprintf(stderr, "%s\n", "Command contains non UTF-8 symbols, abborted");
        return 0;
    }
    char *command_string = json_dumps(package, JSON_ENCODE_ANY);
    assert(command_string);
    zframe_t *command_frame = zframe_new (command_string, strlen(command_string));
    zmsg_push (msg, command_frame);
    zmsg_send (&msg, socket);

    //cleanup
    free(package);
    free(command_string);
    return 1;
}

// read input from stdin to configure the gateway at runtime
static void *input_loop (void *args){
    UNUSED(args);
    // prepare connection to main thread
    zctx_t *input_ctx = zctx_new();
    /* for stopping the client and the gateway handler via keystroke (ctrl-c) */
    s_catch_signals();

    char *control_socket_adress = NULL;
    int rc;

    void *input_handler = zsocket_new (input_ctx, ZMQ_DEALER);
    assert(input_handler);

    control_socket_adress = getenv(CTRL_TARGET_ENV);
    if (!control_socket_adress) {
        fprintf(stderr, "%s not specified, choosing the default (tcp://127.0.0.1:27001)\n", CTRL_TARGET_ENV);
        control_socket_adress = "tcp://127.0.0.1:27001";
    }

    rc = zsocket_connect (input_handler, control_socket_adress);
    assert(!rc);

    zmq_pollitem_t items[] = {
        { input_handler, 0, ZMQ_POLLIN, 0},
    };

    // input loop
    rc = 0;
    char *command, *argument;
    do{
        fprintf(stdout, "Input commands to change configuration of the Gateway (to get an overview about all possible inputs, type \"help\".\n");
        parse_command(&command, &argument);
        // send command to main thread
        rc = send_command(input_handler, command, argument);
        //sending failed, begin anew
        if(rc == 0){
            continue;
        }
        fprintf(stdout, "%s\n", "waiting for acceptance of command...");
        // wait for reaction of the main thread
        rc = zmq_poll(items, 1, 5000);
        if(rc == -1){
            // error in zmq poll
        }
        // got a response from the main thread before timeout
        if (items[0].revents & ZMQ_POLLIN){
            char *response = zstr_recv(input_handler);
            if(strcmp(response, CTRL_UKCOM) == 0){
                fprintf(stdout, "%s\n", "command unknown");
            }
            else if(strcmp(response, CTRL_ACCEPTED) == 0){
                fprintf(stdout, "%s\n", "command accepted");
            }
            else{
                fprintf(stdout, "Response:\n%s\n", response);
            }
            free(response);
        }
        // no response from main thread before timeout
        else{
            fprintf(stdout, "%s\n", "command not accepted. (timeout)");
        }

        //cleanup
        free(command);
        free(argument);
    }while(false);

    //cleanup
    zsocket_destroy(input_ctx, input_handler);
    zctx_destroy(&input_ctx);

    return NULL;
}

int main (){
    input_loop(0);
    return 0;
}
