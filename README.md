# jping
This program check if a node on the internet is online. Sends and receives icmp packets and uses the received packet to print out some information
It allows you to either use the hostname or the ip address of the host to ping it. 
NOTE: You  need root  privileges to be able to run this program as it uses raw sockets. 

EXAMPLE

gcc -g jping.c



sudo ./a.out www.google.com
