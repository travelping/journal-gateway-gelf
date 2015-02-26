zmq-journal-gatewayd
====================

A ZeroMQ gateway for sending logs from systemd's journald over the network and a client (both CLI tools).

Logs are available in plain text or an 'export' format suitable for storing them back (with journal-remote) into some systemd journal like

```bash
zmq-journal-gatewayd-client | systemd-journal-remote -o /path/to/some/dir/ -
```
Mind the - at the end.
If you want to use the gateway as a relay you need to store the received logs into the local journal directory:
```bash
zmq-journal-gatewayd-client | systemd-journal-remote -o /var/log/journal/[machine-id]
```

Use --help for an overview of all commands.

Mode of Operation
-----------------

      +----------------+
      |    journald    |
      |                |
      |                |+------------+
      |                |             |
      |                |             |syslog
      +----------------+             |live forwarding
      +-----+ |                      |udp:514
      |file | |                      |udp:broadcast
      +-----+ | journal_api          |
              |                      |
              v                      v
      +----------------+ syslog  +------------+
      |   "gateway"    |-------->| SYSLOG     |
      |                |         +------------+
      |    acts as     |
      |    journal     | GELF    +------------+
      |    client      |-------->| GRAYLOG2   |
      |                |         +------------+
      |                |                                         +--------------+
      |                | HTTP    +---------------------------+   |   journald   |
      |                |-------->| HTTP |     journald-remote|-->|              |
      |                |         +---------------------------+   |              |
      |                |                                         |              |
      |                | ZMTP    +------+    +---------------+   |              |
      |                |-------->| ZMTP |--->|journald-remote|-->|              |
      |                |         +------+    +---------------+   |              |
      |                |                                         |              |
      |                |                                         |              |
      +----------------+                                         +--------------+
                                                                 +-----+  +-----+
                                                                 |file |  |file |
                                                                 +-----+  +-----+


Installation
------------

You will need [ZeroMQ](http://zeromq.org/intro:get-the-software) (recomended version: 3.2.5, you'll need >= 3), [czmq](https://github.com/zeromq/czmq#toc3-71)  (ZeroMQ C bindings), jansson and the systemd-headers (for the gateway only). The gateway and the client can be build seperately (thus you dont need systemd for the client). Using Fedora you can do:

```bash
yum install jansson jansson-devel systemd-devel
```

for jansson and systemd. To install ZMQ and CZMQ follow the instructions on  the linked sites.


Then just execute (in the zmq-journal-gatewayd directory):

```bash
cd build

make all	        # you can also just build the gateway or the client 
                	# with 'make gateway' or 'make client' 

sudo make install	# puts the binaries to /usr/bin; 
               		# 'make install_gateway' or 'make install_client' is also
                	# possible
sudo ldconfig
```

Usage
-----

Installing the gateway will also install a service file to execute the gateway as a systemd unit:

```bash
systemctl start zmq-journal-gatewayd    # binds by default on "tcp://*:5555"
```

If you need other sockets you can write a configuration file for the service:
The service looks for a configuration file named "zmq_gateway.conf" in the directory "~/conf". You can change the socket there (this only has an effect, if you execute the gateway as a systemd unit).


You can start the client via:
```bash
zmq-journal-gatewayd-client [options]
```
