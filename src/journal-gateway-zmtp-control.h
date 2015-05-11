/* definitions for controlling communication */
#define CTRL_LOGON "\001"	// initialise connection
#define CTRL_READY "\002"	// signal that initiation of connection finished
#define CTRL_LOGOFF "\003"	// stop connection
#define CTRL_UKCOM "\005" // signals that the received command was not understood (unknown)
#define CTRL_ACCEPTED "\006" // signals the the received command was accepted
#define DEFAULT_CONTROL_SOCKET "tcp://*:27001"
#define CTRL_TARGET_ENV "GATEWAY_CONTROL_TARGET"
