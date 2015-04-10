journal-gateway-zmtp
====================

A ZeroMQ gateway for sending logs from systemd's journald over the network and a sink (both CLI tools).

Logs are stored in a journalfile, separated for each source.

Configuration while Running
---------------------------

== Enhanced Control for the ZMTP-Journal-Gateway

To enable configuration of both sink and source during runtime the following API and connection is going to be implemented.

----
+--------------+     ZMTP connection                     +------------+              
|gateway source+--------------------------------->)------+gateway sink|              
+-----+--------+     for control communication           +-+----------+              
      |              between source and sink               |                         
      |API                                                 |API                      
      |        +----------+                                |      +----------------+ 
      +--------+set_target|                                +------+set_exposed_port| 
      |        +----------+                                |      +----------------+ 
      |                                                    |                         
      |        +----------+                                |      +-----------------+
      +--------+set_filter|                                +------+set_log_directory|
      |        +----------+                                |      +-----------------+
      |                                                    |                         
      |        +-------------+                             |      +------------+     
      +--------+set_sourcelog|                             +------+show_sources|     
               +-------------+                             |      +------------+     
                                                           |                         
                                                           |      +----------+       
                                                           +------+set_filter|       
                                                                  +----------+       
----
A more precise description of the API is coming along the road.

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
