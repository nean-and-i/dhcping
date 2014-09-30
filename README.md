dhcping v1.4fbeta


DHCP test and autiting tool!

USE DHCPDUMP FOR MONITORING PURPOSES!
WARNING: FOR DHCP TESTING PURPOSES ONLY!

RESPECT COPYRIGHT!


 
usage: dhcping -c <ciaddr> -g <giaddr> -h <chaddr> -s <server-ip>  
 
options:  
 -c <ciaddr>      -> Client IP Address  
 -g <giaddr>      -> Gateway IP Address  
 -h <chaddr>      -> Client Hardware Address  
 -s <server-ip>   -> Server IP Address  
 
 -q               -> quiet  
 -v               -> verbose output  
 -t <maxwait>     -> timeout (sec.) 
 
DHCP Options: 
 -p <vendor-mode> -> option 60 vendor class id string ( eg. "docsis" max.10 char!)  
 -o <relay-mac>   -> option 82 remote id, macadress of dhcp relay agent  
 
DHCP Message Types (53): 
 -d               -> (1) discover   
 -r               -> (3) request  
 -n               -> keep lease active after a request (no auto release)  
 -f               -> (4) decline  
 -e               -> (7) release  
 -i               -> (8) inform  
 -l               -> (19) leasequery (requesting: 51,60,61,82) ");
