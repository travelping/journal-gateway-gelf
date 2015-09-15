journal-gateway-zmtp
====================

A ZeroMQ gateway for sending logs from systemd's journald over the network and a
sink.

Logs are stored in a journalfile, separated for each source.

Mode of Operation
-----------------

```
  +----------------+
  |    journald    |
  |                |
  |                |
  |                |
  |                |
  +-------+--------+
  +-----+ | +-----+
  |file | | |file |
  +-----+ | +-----+
          | journal_api
          |
          |
  +-------+--------+
  |"gateway-source"|
  |                |
  |    acts as     |
  |    journal     |
  |    client      |
  |                |
  |                |                                         +--------------+
  |                |                                         |   journald   |
  |                |                                         |              |
  |                |                                         |              |
  |                |                                         |              |
  |                | ZMTP    +------+    +---------------+   |              |
  |                +---------+ ZMTP +----+"gateway-sink" +---+              |
  |                |         +------+    |uses           |   |              |
  |                |                     |systemd-journal|   |              |
  |                |                     |-remote        |   |              |
  +----------------+                     +---------------+   +-----+--+-----+
                                                             +-----+  +-----+
                                                             |file |  |file |
                                                             +-----+  +-----+
```
Installation
------------

You will need [ZeroMQ](http://zeromq.org/intro:get-the-software) (recomended
version: 3.2.5, you'll need >= 3),
[czmq](https://github.com/zeromq/czmq#toc3-71)  (ZeroMQ C bindings), jansson
and the systemd-headers (for the gateway only). The gateway and the client can
be build seperately (thus you dont need systemd for the client). Using Fedora
you can do:

```bash
yum install jansson jansson-devel systemd-devel
```

for jansson and systemd. To install ZMQ and CZMQ follow the instructions on
the linked sites.


Then just execute (in the journal-gateway-zmtp directory):

```bash
make              # you can also just build the gateway or the client
                  # with 'make source' or 'make sink'
```

To install the files into your system, you can call the install script in
/sample

Usage
-----

### gateway-sink

You should start the sink first. It binds to the specified socket and waits for
an incomming connection from a gateway. If you want it to stay listening for
more than one connection, you should start it with the --listen flag.

You can start the sink via:
```bash
env JOURNAL_REMOTE_DIR=[some_path] GATEWAY_LOG_PEER=[some_peer] ~/dev/tobzmq/journal-gateway-zmtp-sink --listen
```

You must specify a peer (in GATEWAY_LOG_PEER) on which the sink binds and
expects sources to log on. You must also specify a directory (in
JOURNAL_REMOTE_DIR) in which you want to save your remote journals. The journal
file names are based on the IDs of the gateways. Every new gateway-sink
connection will be logged in the journal:

```bash
Mär 02 09:58:42 virtual-fedora-sbs journal-gateway-zmtp-sink[9623]: gateway has a new source, ID: 006B8B4567
```

### gateway-source

Installing the gateway will also install a service file to execute the gateway
as a systemd unit:

```bash
systemctl start journal-gateway-zmtp-source    # connects by default to "tcp://127.0.0.1:5555"
```

The service looks for a configuration file named "zmq_gateway_source.conf" in
the directory "~/conf". You can change the socket there (this only has an
effect, if you execute the gateway as a systemd unit).

If you want to start the gateway without using systemd, you can type
```bash
env JOURNAL_REMOTE_TARGET=[some_peer] JOURNAL_SOURCE_DIR=[some_path] ~/dev/tobzmq/journal-gateway-zmtp-source
```

where JOURNAL_REMOTE_TARGET defines the exposed socket of the sink and
JOURNAL_SOURCE_DIR the target socket for the logs.

Use --help for an overview of all commands.

Configuration while Running
---------------------------

###Enhanced Control for the ZMTP-Journal-Gateway

To enable configuration of both sink and source during runtime the following API
and connection is implemented. Both parts of the gateway expose a port on which
a tool can connect via ZeroMQ. The gateway offers the journal-gateway-zmtp-
control which is a simple one line input tool. Both expect a json encoded string
which contains a json_object (a dictionary of key-value pairs) with only one
pair. The key contains the command and the value contains the arguments if any.
The sink/source then checks if the command matches one of the valid commands.
The source of the control command then receives a message: If succesfully
matched the command gets executed and CTRL_ACCEPTED or the requested information
is returned (for example a list of all connected logging sources is returned
from the sink). If the match failed CTRL_UKCOM is returned.


```
+---------------+    ZMTP connection                     +------------+
|gateway control+-------------------------------->)+-----+gateway sink|
+---------------+    for control communication           +-+----------+
                     sink exposes a tcp port               |
                     (default tcp://*:27001)               |
                     which expects control signals         |      +----------------+
                     that leads to calls of the API        +------+set_exposed_port|
                                                           |      +----------------+
                     (the most important are shown to      |
                      the right, further explanations      |      +-----------------+
                      see below)                           +------+set_log_directory|
                                                           |      +-----------------+
                                                           |
                                                           |      +------------+
                                                           +------+show_sources|
                                                           |      +------------+
                                                           |
                                                           |      +-----------+
                                                           +------+show_filter|
                                                           |      +-----------+
                                                           |
                                                           |      +----------+
                                                           +------+shutdown  |
                                                           |      +----------+
                                                           |
                                                           |
                                                         (...) see below
```

It follows a list of all valid commands:

* help
    - will show a short version of this chapter

* show_exposed_port
    - will show the endpoint chosen in GATEWAY_LOG_PEER if not otherwise set
    - this is the port on which the logs sent by the source are received

* set_exposed_port <port>
    - will set the endpoint
    - Example: set_exposed_port tcp://127.0.0.1:5555

* show_sources
    - will show the zmq ids of each connection to journal-gateway-zmtp-sources

* show_log_directory
    - will show the directory in which the journal files are stored

* set_log_directory <dir>
    - will set the directory
    - will create the directory if it doesn't exist at the time of the call
    - Example: set_log_directory /var/log/example/

* show_diskusage
    - shows the used disc space of the directory in which the logs are stored
    - the shown number is the number of used blocks

* shutdown
    - will stop the sink

The following commands will change the applied filters.
This is implemented in a set and commit manner, meaning that the changes you choose will only apply after you commit them.
The filters have to be written in the same way ``journalctl`` expects the matches (FIELD=value).
The filters are applied in the sources, changing the filters in the sink will lead to a broadcast of the new filters to all sources, changing the filters globally.

* filter_add FIELD=value
    - will add the matching FIELD=value to the filters
    - successively added filters are ORed together
    - Example: filter_add PRIORITY=4

* filter_add_conjunction
    - will add a logical AND to the list of filters

* filter_flush
    - will drop all currently set filters

* filter_show
    - will show the currently set filters
    - will also show the currently active filters

* filter_commit
    - will apply the currently set filters
    - WARNING: will set the same filter on **every** source


```
+---------------+    ZMTP connection                     +--------------+
|gateway control+-------------------------------->)+-----+gateway source|
+---------------+    for control communication           +-+------------+
                     sink exposes a tcp port               |
                     (default tcp://*:27002)               |
                     which expects control signals         |      +----------------+
                     that leads to calls of the API        +------+set_target_port |
                                                           |      +----------------+
                     (the most important are shown to      |
                      the right, further explanations      |      +-----------+
                      see below)                           +------+show_filter|
                                                           |      +-----------+
                                                           |
                                                           |      +----------+
                                                           +------+shutdown  |
                                                           |      +----------+
                                                           |
                                                           |
                                                         (...) see below
```


This chapter contains short explanation for each command one can send to the journal-gateway-zmtp-source.

* help
    - will show a short version of this chapter

* show_target_port
    - will show the endpoint chosen in JOURNAL_REMOTE_TARGET if not otherwise set

* set_target_port <port>
    - will set the endpoint
    - Example: set_target_port tcp://127.0.0.1:5555

* show_log_directory
    - will show the directory from which the logs are read

* set_log_directory <dir>
    - will set the directory from which the logs are read

* shutdown
    - will stop the source

The handling of the filters in the source is the same as in the sink.

Example
-------

Start the sink:
```bash
env JOURNAL_REMOTE_DIR=~/logtest GATEWAY_LOG_PEER=tcp://127.0.0.1:5555 ~/dev/tobzmq/journal-gateway-zmtp-sink --listen
```
Start the source:
```bash
env JOURNAL_REMOTE_TARGET=tcp://127.0.0.1:5555 JOURNAL_SOURCE_DIR=/var/log/journal ~/dev/tobzmq/journal-gateway-zmtp-source
```

This will write everything in your journal into a journal file in the specified directory.
```bash
journalctl --directory ~/logtest -f
```
