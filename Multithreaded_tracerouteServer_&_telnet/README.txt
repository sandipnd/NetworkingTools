***************README file for tracerouteserver*******************

9/25/2012

CONTENTS OF PACKAGE P538_Project1
-trcServer.cpp   : server code file
-util.cpp	 : code containing server supporting functions
-trcServer.h     : server header file
-Makefile        
-trfile          : file containing some host names
-trcClient.cpp   : client code file



Instructions to Execute:
-------------------------

1.Run make file
2.Give the command line arguments as follows:

./tracerouteServer -p [#port] -m [max_users] -d [strict_dest] -u [max_cmds] -r [max_time]


Default values:

port : 1216
max_users: 2
strict_dest: 0
max_cmds : 4
max_time: 60


Instructions to Execute Client:
-------------------------------

1.Run the following command
 
  g++ -o tracerouteClient trcClient.cpp
  ./tracerouteClient [server] [port]


server - IP address of server
port   - port number on which the server is running.

