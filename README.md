zmq-journal-gatewayd
====================

A ZeroMQ gateway for sending logs from systemd's journald over the network and a client (both CLI tools).

Logs are available in plain test or an 'export' format suitable for storing them back (with journal-remote) into some systemd journal like

```bash
zmq-journal-gatewayd-client | systemd-journal-remote -o /path/to/some/dir/ -
```

Use --help for an overview of all commands.

Installation
------------

You will need ZeroMQ >=3, czmq (ZeroMQ C bindings), jansson and the systemd-headers (for the gateway only). The gateway and the client can be build seperately (thus you dont need systemd for the client). Using Fedora you can do:

```bash
yum install czmq jansson jansson-devel systemd-devel
```

Then just execute:

```bash
cd build

make all        # you can also just build the gateway or the client 
                # with 'make gateway' or 'make client' 

make install    # puts the binaries to /usr/share/zmq-journal-gatewayd; 
                # 'make install_gateway' or 'make install_client' is also
                # possible
```

Installing the gateway will also install a service file to execute the gateway as a systemd unit:

```bash
systemctl start zmq-journal-gatewayd    # binds by default on "tcp://*:5555"
```

If you need other sockets you can write a configuration file for the service.

