journal-gateway-zmtp
====================

A gateway for transmitting of systemds journal via a zmtp connection.

Version 1.0.0 - 07 Jul 2015
---------------------------

* Fixed overloading issue of the sink with ZMQ Versions < 3.0.0

Version 1.0.0 - 07 Jul 2015
---------------------------

* The controls are now more intuitive:
    * Setting filters works in a set and commit fashion
    * Everything that can be set can also be shown
* The Sink now saves the logs in directories coresponding to the machine-id of the origin of the logging message
* The Sink now changes the timestamps of the messages, generating a global monotony of the received messages

Version 0.9.1 - 20 May 2015
---------------------------

* The Source is now configurable in runtime

Version 0.9.0 - 11 May 2015
---------------------------

* Unit tests and general helper functions for tests added
* The Sink is now configurable in runtime

Version 0.8.1 - 25 Mar 2015
---------------------------

* Target directory now gets automatically created
* A Bug is fixed, where the sink crashed if no valid machine id could be found

Version 0.8.0 - 04 Mar 2015
---------------------------

* Support for several sources and one sink
* Can be started and configured via systemd service- & .conf-files
