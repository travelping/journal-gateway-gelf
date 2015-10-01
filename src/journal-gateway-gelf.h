#include "jansson.h"
#include <curl/curl.h>
#include <getopt.h>

/* definitions for internal communication between gateway and client */
#define READY "\001"
#define END "\002"
#define HEARTBEAT "\003"
#define ERROR "\004"
#define TIMEOUT "\005"
#define STOP "\006"
#define LOGON "\007"
#define LOGOFF "\010"

// seconds:   100 micro  1.5 milli    500 milli
#define SLEEP 100000L // 1500000L //  500000000L

#define UNUSED(x) (void)(x)

#define VMAYOR 1
#define VMINOR 0
#define VPATCH 0

typedef int bool;
#define true 1
#define false 0
