journal-gateway-gelf
====================

A gateway for sending logs from systemd's journald over an HTTP connection to a
Graylog server in GELF format.

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
  |                |                                         |   graylog    |
  |                |                                         |   server     |
  |                |                                         |              |
  |                |                                         |              |
  |                | HTTP(GELF formatted)                    |              |
  |                +-----------------------------------------+              |
  |                |                                         |              |
  |                |                                         |              |
  |                |                                         |              |
  +----------------+                                         +-----+--+-----+
```
Build
-----

You will need jansson, libcurl and the systemd-headers.

Then just execute (in the journal-gateway-gelf directory):

```bash
make
```

To install the files into your system, you can call the install script in
/sample

Usage
-----

### gateway-source

Installing the gateway will also install a service file to execute the gateway
as a systemd unit:

```bash
systemctl start journal-gateway-gelf-source
```

The service looks for a configuration file named  "journal-gateway-gelf-
source.conf" in the etc directory. You can change the socket there (this
only has an effect, if you execute the gateway as a systemd unit).

If you want to start the gateway without using systemd, you can type
```bash
JOURNAL_REMOTE_TARGET=[some_peer] JOURNAL_SOURCE_DIR=[some_path] ./journal-gateway-gelf-source
```

where JOURNAL_REMOTE_TARGET defines the input of the graylog server and
JOURNAL_SOURCE_DIR the source folder for the logs.

Use --help for an overview of all commands.

## Configuration

You can change two parameters in /etc/journal-gateway-gelf-source.conf:

```
JOURNAL_REMOTE_TARGET="http://127.0.0.1:12345/gelf"
JOURNAL_SOURCE_DIR="/var/log/journal/"
```

which changes the target and the source folder of the logs.
Mind the format of the target if you want to send messages to a graylog server.

Example
-------

Start the source:

```bash
env JOURNAL_REMOTE_TARGET=tcp://127.0.0.1:1234 JOURNAL_SOURCE_DIR=/var/log/journal ./journal-gateway-zmtp-source
```

This will send every new message in your journal to the graylog server.
