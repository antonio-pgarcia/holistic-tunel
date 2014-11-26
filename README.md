# holistic-tunel #

A reverse proxy plugin for SunOne web server

## Prerequisites ##

The plugin requires the curl library [libcurl](http://curl.haxx.se/libcurl/). You can find a pre-compuled version suitable for your operating system at [download page](http://curl.haxx.se/download.html).

The plugin requires 

## Compiling ##

A **Makefile** is provided to compile the software. Just invoke from command line the command **make** and the plugin shared object will be generated. The library filename is **holistic35.so**. Please make sure to modify the **NS_HOME** variables inside the **Makefile** according to the actual path for SunOne webserver installation. For example, assuming you have installed the webserver at **/usr/apps/SUNWwbsvr**, the value of config variable must be:

**NS_HOME=/apps/develop/apps/SUNWwbsvr**


## Installing ##

To install the softeare just 

## Configuring SunOne web server ##
