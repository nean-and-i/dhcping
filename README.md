# dhcping v1.4f


DHCP test and autiting tool!

USE DHCPDUMP FOR MONITORING PURPOSES!

WARNING: FOR DHCP TESTING PURPOSES ONLY!



 
```
dhcping v1.4f <neuhold.an@gmail.com>


usage: dhcping -c <ciaddr> -g <giaddr> -h <chaddr> -s <server-ip> 


options: 
 -c <ciaddr>      -> Client IP Address 
 -g <giaddr>      -> Gateway IP Address 
 -h <chaddr>      -> Client Hardware Address 
 -s <server-ip>   -> Server IP Address 

 -q               -> quiet 
 -v               -> verbose output 
 -t <maxwait>     -> timeout (sec.) 


DHCP Message Types (53):
 -d               -> (1)  discover  
 -r               -> (3)  request 
 -f               -> (4)  decline 
 -e               -> (7)  release 
 -i               -> (8)  inform 
 -l               -> (10) leasequery (requesting: 51,60,61,82) 
 -a               -> (13) leaseactive 
 -n               -> keep lease active after a request (no auto release) 


DHCP Options:
 -p <vendor-mode> -> option 60 vendor class id string ( eg. "docsis" max.10 char!) 
 -o <relay-mac>   -> option 82 remote id, macadress of dhcp relay agent 



EXAMPLES: 
  leasequery
    localhost:   10.34.134.217
    dhcp server: 10.34.134.215
    macadress:   28:be:9b:ab:50:ce


  dhcping -v -l -h 28:be:9b:ab:50:ce -g 10.34.134.217 -s 10.34.134.215 
```
