# holistic-tunel #

A reverse proxy plugin for SunOne web server. The plugin is tailored to integrate the jacada interface server for XHTML with web servers.

## Prerequisites ##

The plugin requires the curl library [libcurl](http://curl.haxx.se/libcurl/). You can find a pre-compuled version suitable for your operating system at [download page](http://curl.haxx.se/download.html).


## Building ##

A **Makefile** is provided to compile the software. Just invoke from command line the command **make** and the plugin shared object will be generated. The library filename is **holistic35.so**. Please make sure to modify the **NS_HOME** variables inside the **Makefile** according to the actual path for SunOne webserver installation. For example, assuming you have installed the webserver at **/usr/apps/SUNWwbsvr**, the value of config variable must be:

**NS_HOME=/apps/develop/apps/SUNWwbsvr**


## Installing ##

To install the software just copy the library (**holistic35.so**) and the provided sample config file (**bootstrap.properties**) to the directory of your choice. 

``
#----------------------------------------------------------------------
# Holistic-Tunel l 3.5
# Configuration file (bootstrap.properties)
#----------------------------------------------------------------------
HVTunnel.http.ToURI|http://<THE BACKEND SERVER>
HVTunnel.http.connect.timeout|1
HVTunnel.http.transfer.timeout|1
HVTunnel.http.Redirects|0
HVTunnel.http.Verbose|0
HVTunnel.Logg.Level|1
HVTunnel.Backend.URI|http://<THE AUTH/AUTORIZATION SERVER>
``

## Configuring SunOne web server ##

The second step is modify the sunone config files in order to include the plugin configurarion. The **magnus.conf** and the **obj.conf** must be edited by hand.
