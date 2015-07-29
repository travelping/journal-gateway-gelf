/* definitions for controlling communication */
#define CTRL_LOGON "\001"	// initialise connection
#define CTRL_READY "\002"	// signal that initiation of connection finished
#define CTRL_LOGOFF "\003"	// stop connection
#define CTRL_UKCOM "\005" // signals that the received command was not understood (unknown)
#define CTRL_ACCEPTED "\006" // signals the the received command was accepted
#define DEFAULT_CONTROL_TARGET "tcp://127.0.0.1:27001"
