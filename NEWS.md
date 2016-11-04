journal-gateway-gelf
====================

A gateway for transmitting of systemds journal via HTTP to a graylog server.

Version 1.0.4 - 04 Oct 2016
---------------------------

* added install target to the Makefile (thanks to @jagulli)
* the connection to the graylog server now uses HTTP keep-alive
  (in the course of this change we switched from CURL_HTTP_VERSION_1_0 to
  CURL_HTTP_VERSION_1_1)
* fix seeking of journal-cursor upon startup which lead to the sending of
  random old messages

Version 1.0.3 - 16 Mar 2016
---------------------------

* fix memory leaks

Version 1.0.2 - 02 Oct 2015
---------------------------

* fix libcurl usage
* renaming gateway-gelf-source -> gateway-gelf

Version 1.0.1 - 02 Oct 2015
---------------------------

* fix default config

Version 1.0.0 - 01 Oct 2015
---------------------------

* initial commit
