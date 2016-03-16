journal-gateway-gelf
====================

A gateway for sending logs from systemd-journald over a HTTP connection to a
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
  |   "gateway"    |
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
``/sample``

Usage
-----

### gateway

Installing the gateway will also install a service file to execute the gateway
as a systemd unit:

```bash
systemctl start journal-gateway-gelf
```

The service looks for a configuration file named  ``"journal-gateway-gelf.conf``
in the ``/etc`` directory. You can change the socket there (this only has an
effect, if you execute the gateway as a systemd unit).

If you want to start the gateway without using systemd, you can run
```bash
JOURNAL_GELF_REMOTE_TARGET=[some_peer] JOURNAL_GELF_SOURCE_DIR=[some_path] ./journal-gateway-gelf
```

where `JOURNAL_GELF_REMOTE_TARGET` defines the input of the graylog server and
`JOURNAL_GELF_SOURCE_DIR` the source folder for the logs.

Use `--help` for an overview of all commands.

## Configuration

You can change two parameters in `/etc/journal-gateway-gelf.conf`:

```
JOURNAL_GELF_REMOTE_TARGET="http://127.0.0.1:12345/gelf"
JOURNAL_GELF_SOURCE_DIR="/var/log/journal/"
```

which chang the target URL and the source folder of the logs.
Mind the format of the target if you want to send messages to a graylog server.

Example
-------

Start the gateway:

```bash
env JOURNAL_GELF_REMOTE_TARGET=http://127.0.0.1:1234/gelf JOURNAL_GELF_SOURCE_DIR=/var/log/journal ./journal-gateway-gelf
```

This will send every new message in your journal to the graylog server.
