journal-gateway-zmtp
====================

A ZeroMQ gateway for sending logs from systemd's journald over the network and a sink (both CLI tools).

Logs are stored in a journalfile, separated for each source.

Configuration while Running
---------------------------

###Enhanced Control for the ZMTP-Journal-Gateway

To enable configuration of both sink and source during runtime the following API and connection is implemented.

```
+---------------+    ZMTP connection                     +------------+
|gateway control+-------------------------------->)+-----+gateway sink|
+---------------+    for control communication           +-+----------+
                     sink exposes a tcp port               |
                     (default tcp://*:5557)                |
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
                                                           |      +----------+
                                                           +------+show_filter
                                                           |      +----------+
                                                           |
                                                           |      +----------+
                                                           +------+shutdown  |
                                                           |      +----------+
                                                           |
                                                           |
                                                         (...) see below
```

The sink exposes a port on which a tool can connect via ZeroMQ. The gateway offers the journal-gateway-zmtp-control which is a simple one line input tool. The sink expects a json encoded string which contains a json_object (a dictionary of key-value pairs) with only one pair. The key contains the command and the value contains the arguments if any. The sink then checks if the command matches one of the valid commands. The source of the control command then receives a message: If succesfully matched the command gets executed and CTRL_ACCEPTED or the requested information is returned (for example a list of all connected logging sources is returned). If the match failed CTRL_UKCOM is returned.

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




Mode of Operation
-----------------


          +----------------+
          |    journald    |
          |                |
          |                |
          |                |
          |                |
          +-------+--------+
          +-----+ |
          |file | |
          +-----+ | journal_api
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
          |                |         +------+    |uses jrd-remote|   |              |
          |                |                     +---------------+   |              |
          |                |                                         |              |
          +----------------+                                         +-----+--+-----+
                                                                     +-----+  +-----+
                                                                     |file |  |file |
                                                                     +-----+  +-----+

Installation
------------

You will need [ZeroMQ](http://zeromq.org/intro:get-the-software) (recomended version: 3.2.5, you'll need >= 3), [czmq](https://github.com/zeromq/czmq#toc3-71)  (ZeroMQ C bindings), jansson and the systemd-headers (for the gateway only). The gateway and the client can be build seperately (thus you dont need systemd for the client). Using Fedora you can do:

```bash
yum install jansson jansson-devel systemd-devel
```

for jansson and systemd. To install ZMQ and CZMQ follow the instructions on the linked sites.


Then just execute (in the journal-gateway-zmtp directory):

```bash
make              # you can also just build the gateway or the client
                  # with 'make source' or 'make sink'
```

Usage
-----

### gateway-sink

You should start the sink first.
It binds to the specified socket and waits for an incomming connection from a gateway.
If you want it to stay listening for more than one connection, you should start it with the --listen flag.

You can start the sink via:
```bash
env JOURNAL_DIR=[journal directory] journal-gateway-zmtp-sink [options]
```
You must specify a directory in which you want to save your remote journals (set via environment variable JOURNAL_DIR).
The journal file names are based on the IDs of the gateways.
Every new gateway-sink connection will be logged in the journal:

```bash
Mär 02 09:58:42 virtual-fedora-sbs journal-gateway-zmtp-sink[9623]: gateway has a new source, ID: 006B8B4567
```

If you want to use this tool as a relay you need to store the received logs into the local journal directory:
```bash
env JOURNAL_DIR=/var/log/journal/[machine-id] journal-gateway-zmtp-sink
```

This way the gateway can access this journal files and will forward them to the next sink.

### gateway

Installing the gateway will also install a service file to execute the gateway as a systemd unit:

```bash
systemctl start journal-gateway-zmtp-source    # connects by default to "tcp://127.0.0.1:5555"
```

If you need other sockets you can write a configuration file for the service:
The service looks for a configuration file named "zmq_gateway_source.conf" in the directory "~/conf". You can change the socket there (this only has an effect, if you execute the gateway as a systemd unit).

If you want to start the gateway without using systemd, you can type
```bash
env TARGET_ADDR=[sink adress] journal-gateway-zmtp-source
```
where [sink adress] is the exposed socket of the sink.

Use --help for an overview of all commands.

Example
-------

Start the sink:
```bash
env JOURNAL_DIR=~/logs/remote/ journal-gateway-zmtp-sink --listen
```
Start the gateway:
```bash
env TARGET_ADDR=tcp://127.0.0.1:5555 journal-gateway-zmtp-source
```

This will write everything in your journal into a journal file in the specified directory.
You can check this by accessing this new file with journal control:
```bash
journalctl --file ~/logs/remote/[some id].journal
```
