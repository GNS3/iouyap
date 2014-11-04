iouyap
======

Bridge IOU to UDP, TAP and Ethernet.

Installation on Linux (Debian based)
------------------------------------

.. code:: bash

   sudo apt-get install git bison flex

   git clone http://github.com/ndevilla/iniparser.git
   cd iniparser
   make
   sudo cp libiniparser.* /usr/lib/
   sudo cp src/iniparser.h /usr/local/include
   sudo cp src/dictionary.h /usr/local/include

   git clone https://github.com/GNS3/iouyap.git
   cd iouyap
   make
   chmod +x iouyap
   sudo cp iouyap /usr/local/bin/
