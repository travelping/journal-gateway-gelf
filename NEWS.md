journal-gateway-zmtp
====================

A gateway for transmitting of systemds journal via a zmtp connection.


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
