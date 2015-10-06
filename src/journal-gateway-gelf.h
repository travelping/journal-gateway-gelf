#include "jansson.h"
#include <curl/curl.h>
#include <getopt.h>

#define BACKEND_SOCKET "ipc://backend"          // used by the query handler
#define ENV_LOG_TARGET_SOCKET "JOURNAL_GELF_REMOTE_TARGET"
#define ENV_JOURNAL_SOURCE_DIRECTORY "JOURNAL_GELF_SOURCE_DIR"
#define ENV_SINCE_TIMESTAMP "JOURNAL_EXPORT_FROM"
#define ENV_UNTIL_TIMESTAMP "JOURNAL_EXPORT_TO"
#define ENV_BOOT "JOURNAL_EXPORT_BOOT_ID"

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
