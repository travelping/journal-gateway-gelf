journal-gateway-zmtp
====================

A ZeroMQ gateway for sending logs from systemd's journald over the network and a
sink.

Logs are stored in a journalfile, separated for each source.

Mode of Operation
-----------------


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

It follows a list of all valid commands and example arguments:


command           | argument type | example argument    | explanation
------------------|---------------|---------------------|------------
reverse¹          | 0, 1          | 0                   | 0 (default) - output in normal direction, 1 - inverse direction
at_most¹          | int           | 5                   | only this many messages will be sent
since_timestamp   | timestamp     | 2014-10-01 18:00:00 | shows only logs since the specified timestamp
until_timestamp¹  | timestamp     | 2014-10-01 18:00:00 | shows only logs until the specified timestamp
since_cursor¹     | journalcursor | ²                   | shows only logs since the specified cursor
until_cursor      | journalcursor | ²                   | shows only logs until the specified cursor
follow            | 0, 1          | 1                   | 0 - doesn't follow the journal for new entries, 1 (default) - follows
filter            | filter string | [["MESSAGE=a"]]     | the sources will only send entries matching the filter ³
listen            | 0, 1          | 1                   | 0 - the sink will stop if the first source logs off, 1 (default) - the sink waits indefinitely for incomming connections
set_exposed_port  | zmtp port     | 5556                | changes the port on which the sinks listens for incomming log messages
set_log_directory | path          | /home/user/logtest  | changes the directory in which the messages are stored
show_filter       | none          |                     | returns a string of the currently set filters
show_sources      | none          |                     | returns a string of the currently logged on sources
send_query        | none          |                     | the sink triggers all sources to send journals according to the set filters
shutdown          | none          |                     | shuts down the sink
help              | none          |                     | shows a short version of this table
1: only usable if listen is deactivated

2: s=a4b70ccdcd4a4fc5a52e168eea246e05;i=1;b=0e7e1cc42bdd4028835611b65f2adc

3: requires input of the form e.g. [["FILTER_1", "FILTER_2"], ["FILTER_3"]] this example reprensents the boolean formula "(FILTER_1 OR FILTER_2) AND (FILTER_3) whereas the content of FILTER_N is matched against the contents of the logs


```
+---------------+    ZMTP connection                     +--------------+
|gateway control+-------------------------------->)+-----+gateway source|
+---------------+    for control communication           +-+------------+
                     sink exposes a tcp port               |
                     (default tcp://*:27002)               |
                     which expects control signals         |      +----------------+
                     that leads to calls of the API        +------+set_target_peer |
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
command           | argument type | example argument    | explanation
------------------|---------------|---------------------|------------
reverse           | 0, 1          | 0                   | 0 (default) - output in normal direction, 1 - inverse direction
at_most           | int           | 5                   | only this many messages will be sent
since_timestamp   | timestamp     | 2014-10-01 18:00:00 | shows only logs since the specified timestamp
until_timestamp   | timestamp     | 2014-10-01 18:00:00 | shows only logs until the specified timestamp
since_cursor      | journalcursor | ¹                   | shows only logs since the specified cursor
until_cursor      | journalcursor | ¹                   | shows only logs until the specified cursor
follow            | 0, 1          | 1                   | 0 - doesn't follow the journal for new entries, 1 (default) - follows
filter            | filter string | [["MESSAGE=a"]]     | the sources will only send entries matching the filter ³
set_target_peer   | zmtp port     | 5556                | changes the port on which the sinks listens for incomming log messages
show_filter       | none          |                     | returns a string of the currently set filters
apply_filter      | none          |                     | the source is triggered to apply the set filters from now on (until call of this old filters will be applied)
shutdown          | none          |                     | shuts down the source
help              | none          |                     | shows a short version of this table

1: s=a4b70ccdcd4a4fc5a52e168eea246e05;i=1;b=0e7e1cc42bdd4028835611b65f2adc

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
