/*
 * Copyright 2000, 2001, 2002 by Edwin Groothuis, edwin@mavetju.org
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
*/

/*
 *
 * forked from dhcping v1.3
 * modifications by <neuhold.an@gmail.com>
 *
 * dhcping.c,v 1.4f <neuhold.an@gmail.com>
 * changelog: dhcpleaseactive
 *
 * USE DHCPDUMP FOR MONITORING PURPOSES!
 * WARNING: FOR DHCP TESTING PURPOSES ONLY!
 *
 * RESPECT COPYRIGHT!
 *
 * todo:
 * - better handling of option values
 *
*/


#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "dhcp_options.h"

#define BUF_SIZ 256*256
#define uchar unsigned char
#define socklen_t int

int offset=0;
void addpacket(char *pktbuf,char *msgbuf,int size)
{
  memcpy(pktbuf+offset,msgbuf,size);
  offset+=size;
}

void dhcp_setup(char *);
int  dhcp_read(void);
void dhcp_close(void);
void dhcp_dump(unsigned char *buffer,int size);
void dhcp_inform(char *ipaddr,char *gwaddr,char *hardware,char *opt82,char *opt60);
void dhcp_discover(char *ipaddr, char *gwaddr,char *hardware,char *opt82,char *opt60);
void dhcp_request(char *ipaddr,char *gwaddr,char *hardware,char *opt82,char *opt60);
void dhcp_release(char *ipaddr,char *gwaddr,char *hardware);
void dhcp_decline(char *ipaddr,char *gwaddr,char *hardware);
void dhcp_leasequery(char *ipaddr,char *gwaddr,char *hardware);
void dhcp_leaseactive(char *ipaddr,char *gwaddr,char *hardware);
void dhcp_packet(int type,char *ciaddr,char *opt50,char *opt60,char *opt82,char *gwaddr,char *hardware);


int dhcp_socket;
struct sockaddr_in dhcp_to;
int _serveripaddress;
int inform,request,leasequery,leaseactive,decline,discover,norelease,verbose,release,VERBOSE,quiet;
char *ci,*gi,*server,*hw,*opt82mac,*opt60;
unsigned char serveridentifier[4];
int maxwait=3;


void doargs(int argc,char **argv)
{
  char ch;

  inform=request=verbose=VERBOSE=discover=decline=norelease=quiet=release=leasequery=0;
  ci=gi=server="0.0.0.0";
  opt82mac=hw="00:00:00:00:00:00";

  if (argc==1)
    {
      printf("dhcping v1.4f <neuhold.an@gmail.com>\
\n\
\n\
usage: dhcping -c <ciaddr> -g <giaddr> -h <chaddr> -s <server-ip> \
\n\
\n\
options: \n\
 -c <ciaddr>      -> Client IP Address \n\
 -g <giaddr>      -> Gateway IP Address \n\
 -h <chaddr>      -> Client Hardware Address \n\
 -s <server-ip>   -> Server IP Address \n\
\n\
 -q               -> quiet \n\
 -v               -> verbose output \n\
 -t <maxwait>     -> timeout (sec.) \
\n\
\n\
DHCP Message Types (53):\n\
 -d               -> (1)  discover  \n\
 -r               -> (3)  request \n\
 -f               -> (4)  decline \n\
 -e               -> (7)  release \n\
 -i               -> (8)  inform \n\
 -l               -> (10) leasequery (requesting: 51,60,61,82) \n\
 -a               -> (13) leaseactive \n\
 -n               -> keep lease active after a request (no auto release) \
\n\
\n\
DHCP Options:\n\
 -p <vendor-mode> -> option 60 vendor class id string ( eg. \"docsis\" max.10 char!) \n\
 -o <relay-mac>   -> option 82 remote id, macadress of dhcp relay agent \
\n\
\n\
\n\
EXAMPLES: \n\
  leasequery\n\
    localhost:   10.34.134.217\n\
    dhcp server: 10.34.134.215\n\
    macadress:   28:be:9b:ab:50:ce\
\n\
\n\
  dhcping -v -l -h 28:be:9b:ab:50:ce -g 10.34.134.217 -s 10.34.134.215 \
\n\
\n\
");

      exit(1);
    }


  while ((ch = getopt(argc,argv,"c:g:h:iqrefladns:t:o:p:vV"))>0)
    {
      switch (ch)
        {
        case 'c':
          ci=optarg;
          break;
        case 'g':
          gi=optarg;
          break;
        case 'h':
          hw=optarg;
          break;
        case 'i':
          inform=1;
          break;
        case 'q':
          quiet=1;
          break;
        case 'r':
          request=1;
          break;
        case 'l':
          leasequery=1;
          break;
        case 'a':
          leaseactive=1;
          break;
        case 'd':
          discover=1;
          break;
        case 'e':
          release=1;
          break;
        case 'f':
          decline=1;
          break;
        case 'n':
          norelease=1;
          break;
        case 's':
          server=optarg;
          break;
        case 't':
          maxwait=atoi(optarg);
          break;
        case 'o':
          opt82mac=optarg;
          break;
        case 'p':
          opt60=optarg;
          break;
        case 'v':
          VERBOSE=1;
          break;
//        case 'l':
//          optask=optarg;
//          break;
//        case 'V': VERBOSE=1;break;
        }
    }

  //printf("\n\nDEBUG: %s\n\n", opt60);


  if ((request && inform) || (request && discover) || (request && leasequery) || (discover && leasequery) || (inform && leasequery) || (request && leaseactive) || (discover && leaseactive) || (inform && leaseactive))
    {
      fprintf(stderr,"\nError: d,r,l,i,a are mutaully exclusive!\n");
      exit(1);
    }


  if (discover && (ci != "0.0.0.0"))
    {
      fprintf(stderr,"\nError: Discovers does never includes client IP!\n");
      exit(1);
    }


  // DHCPREQUEST is by default.
  if ((!inform && !leasequery && !discover && !release && !decline && !leaseactive ) || request)
    {
      request=1;
      if (ci == "0.0.0.0")
        if (!quiet)
          {
            fprintf(stderr,"\nWarning: but you know, REQUEST needs client IP!\n");
          }
      if ((ci != "0.0.0.0") && (gi != "0.0.0.0"))
        if (!quiet)
          {
            fprintf(stderr,"\nInformation: client ip and gi ip is set, really?\n");
          }
    }
}


// print the data as a 32bits time-value
void printTime32(uchar *data)
{
  int t=(data[0]<<24)+(data[1]<<16)+(data[2]<<8)+data[3];
  if (t==31536000)
    {
      printf("Lease reserved");
    }
  else
    {
      printf("%d sec (",t);
      if (t>7*24*3600)
        {
          printf("%dw",t/(7*24*3600));
          t%=7*24*3600;
        }
      if (t>24*3600)
        {
          printf("%dd",t/(24*3600));
          t%=24*3600;
        }
      if (t>3600)
        {
          printf("%dh",t/3600);
          t%=3600;
        }
      if (t>60)
        {
          printf("%dm",t/60);
          t%=60;
        }
      if (t>0) printf("%ds",t);
      printf(")");
    }
}


////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////


int main(int argc,char **argv)
{
  fd_set read;
  struct timeval timeout;
  int foundpacket=0;
  int returnvalue=0;

  if (geteuid()!=0)
    {
      printf("This program should only be ran by root or be installed as setuid root.\n");
      exit(1);
    }

  doargs(argc,argv);

  //if (VERBOSE) puts("setup");
  dhcp_setup(server);

  if (setuid(getuid())!=0)
    {
      perror("setuid");
      printf("Can't drop privileges back to normal user, program aborted.\n");
      exit(1);
    }

  if (VERBOSE)
    printf("\n---------------------------------------------------------------------------\n\n");
  if (inform)
    {
      if (VERBOSE) puts("DHCP INFORM");
      dhcp_inform(ci,gi,hw,opt82mac,opt60);
    }
  if (request)
    {
      if (VERBOSE) puts("DHCP REQUEST");
      dhcp_request(ci,gi,hw,opt82mac,opt60);
    }
  if (leasequery)
    {
      if (VERBOSE) puts("DHCP LEASEQUERY");
      dhcp_leasequery(ci,gi,hw);
    }
  if (leaseactive)
    {
      if (VERBOSE) puts("DHCP LEASEACTIVE");
      dhcp_leaseactive(ci,gi,hw);
    }
  if (discover)
    {
      if (VERBOSE) puts("DHCP DISCOVER");
      dhcp_discover(ci,gi,hw,opt82mac,opt60);
    }
  if (release)
    {
      if (VERBOSE) puts("DHCP RELEASE");
      dhcp_release(ci,gi,hw);
    }
  if (decline)
    {
      if (VERBOSE) puts("DHCP DECLINE");
      dhcp_decline(ci,gi,hw);
    }

  while (!foundpacket)
    {
      FD_ZERO(&read);
      FD_SET(dhcp_socket,&read);
      timeout.tv_sec=maxwait;
      timeout.tv_usec=0;
      if (select(dhcp_socket+1,&read,NULL,NULL,&timeout)<0)
        {
          perror("select");
          exit(0);
        }
      if (FD_ISSET(dhcp_socket,&read))
        {
          //if (VERBOSE) puts("read");
          /* If a expected packet was found, then also release it. */
          if ((foundpacket=dhcp_read())!=0)
            {
              //dhcp_dump(pktbuf,offset);
              if (request)
                {

// ?decline?
//                  if (discover==1 && decline==1)
//                    {
//                      if (VERBOSE) puts("\n---------------------------------------------------------------------------\n\nDHCP DECLINE");
//                      dhcp_decline(ci,gi,hw);
//                    }

                  if (norelease==0 && decline==0)
                    {
                      if (VERBOSE) puts("\n---------------------------------------------------------------------------\n\nDHCP RELEASE");
                      dhcp_release(ci,gi,hw);
                    }
                }
            }
        }
      else
        {
          if (!quiet)
            fprintf(stderr,"NO ANSWER\n");
          returnvalue=1;
          foundpacket=1;
        }
    }
  if (VERBOSE)
    printf("\n---------------------------------------------------------------------------\n\n");
  //if (VERBOSE) puts("CLOSE");
  dhcp_close();
  return returnvalue;
}


////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////


void dhcp_setup(char *serveripaddress)
{
  struct servent *servent,*clientent;
  struct hostent *hostent;
  int flag;
  struct sockaddr_in name;

  /*
  // setup sending socket
  */
  // to be removed to ensure static compiling, TODO!
  if ((servent=getservbyname("bootps",0))==NULL)
    {
      perror("getservbyname: bootps");
      exit(1);
    }
  if ((hostent=gethostbyname(serveripaddress))==NULL)
    {
      perror("gethostbyname");
      exit(1);
    }

  dhcp_to.sin_family=AF_INET;
  bcopy(hostent->h_addr,&dhcp_to.sin_addr.s_addr,hostent->h_length);
  _serveripaddress=ntohl(dhcp_to.sin_addr.s_addr);
  /*  dhcp_to.sin_addr.s_addr=INADDR_BROADCAST; */
  dhcp_to.sin_port=servent->s_port;

  if ((dhcp_socket=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))==-1)
    {
      perror("dhcp_socket/socket");
      exit(1);
    }

  flag=1;
  if (setsockopt (dhcp_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof flag) < 0)
    {
      perror("dhcp_socket/setsockopt: SO_REUSEADDR");
      exit(1);
    }

  if (setsockopt(dhcp_socket,SOL_SOCKET,SO_BROADCAST,(char *)&flag, sizeof flag) < 0)
    {
      perror ("dhcp_socket/setsockopt: SO_BROADCAST");
      exit(1);
    }

  // to be removed to ensure static compiling, TODO!
  // in some cases needs to be changed from bootps to bootps
  if (leasequery || discover || (gi != "0.0.0.0"))
    {
      if ((clientent=getservbyname("bootps",0))==NULL)
        {
          perror("getservbyname: bootps");
          exit(1);
        }
    }
  else
    {
      if ((clientent=getservbyname("bootpc",0))==NULL)
        {
          perror("getservbyname: bootpc");
          exit(1);
        }
    }

  name.sin_family = AF_INET;
  name.sin_port = clientent->s_port;
  name.sin_addr.s_addr = INADDR_ANY;
  /*  name.sin_addr.s_addr = INADDR_NONE; */
  memset (name.sin_zero, 0, sizeof (name.sin_zero));

  if (bind (dhcp_socket, (struct sockaddr *)&name, sizeof name) < 0)
    {
      perror("bind");
      exit(1);
    }
}

void dhcp_request(char *ipaddr,char *gwaddr,char *hardware,char *opt82,char *opt60)
{
  dhcp_packet(3,ipaddr,ipaddr,opt60,opt82,gwaddr,hardware);
}
void dhcp_decline(char *ipaddr,char *gwaddr,char *hardware)
{
  dhcp_packet(4,ipaddr,NULL,NULL,NULL,gwaddr,hardware);
}
void dhcp_release(char *ipaddr,char *gwaddr,char *hardware)
{
  dhcp_packet(7,ipaddr,NULL,NULL,NULL,gwaddr,hardware);
}
void dhcp_inform(char *ipaddr,char *gwaddr,char *hardware,char *opt82,char *opt60)
{
  dhcp_packet(8,ipaddr,NULL,opt60,opt82,gwaddr,hardware);
}
void dhcp_leasequery(char *ipaddr,char *gwaddr,char *hardware)
{
//  dhcp_packet(10,ipaddr,NULL,NULL,NULL,gwaddr,hardware);
  dhcp_packet(10,ipaddr,NULL,NULL,NULL,gwaddr,hardware);
}
void dhcp_leaseactive(char *ipaddr,char *gwaddr,char *hardware)
{
//  dhcp_packet(13,ipaddr,NULL,NULL,NULL,gwaddr,hardware);
  dhcp_packet(13,ipaddr,NULL,NULL,NULL,gwaddr,hardware);
}
void dhcp_discover(char *ipaddr,char *gwaddr,char *hardware,char *opt82,char *opt60)
{
  dhcp_packet(1,ipaddr,NULL,opt60,opt82,gwaddr,hardware);
}


void dhcp_packet(int type,char *ipaddr,char *opt50,char *opt60,char *opt82,char *gwaddr,char *hardware)
{
  static time_t l=0;
  unsigned char msgbuf[BUF_SIZ];
  unsigned char pktbuf[BUF_SIZ];
  int ip[4],gw[4],hw[16],ip50[4],opt82mac[6];
  int hwcount;

  sscanf(ipaddr,"%d.%d.%d.%d",&ip[0],&ip[1],&ip[2],&ip[3]);

  sscanf(gwaddr,"%d.%d.%d.%d",&gw[0],&gw[1],&gw[2],&gw[3]);

  if (opt50)
    sscanf(opt50,"%d.%d.%d.%d",&ip50[0],&ip50[1],&ip50[2],&ip50[3]);

  if (opt82)
    sscanf(opt82,"%x:%x:%x:%x:%x:%x",&opt82mac[0],&opt82mac[1],&opt82mac[2],&opt82mac[3],&opt82mac[4],&opt82mac[5]);

  //printf("\n\nDEBUG: %s\n\n", opt60);

  memset(&hw,0,sizeof(hw));
  hwcount=sscanf(hardware,"%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x",
                 &hw[0],&hw[1],&hw[2],&hw[3],
                 &hw[4],&hw[5],&hw[6],&hw[7],
                 &hw[8],&hw[9],&hw[10],&hw[11],
                 &hw[12],&hw[13],&hw[14],&hw[15]);

  memset(msgbuf,0,sizeof(msgbuf));
  sprintf(msgbuf,"\1\1%c%c",hwcount,0);
  addpacket(pktbuf,msgbuf,4);

  /* xid */
  if (l>time(NULL))
    l++;
  else
    l=time(NULL);
  memcpy(msgbuf,&l,4);
  addpacket(pktbuf,msgbuf,4);

  /* secs and flags */
  memset(msgbuf,0,4);
  addpacket(pktbuf,msgbuf,4);
  /*  sprintf(msgbuf,"%c%c",0x80,0x00); */
  /*  sprintf(msgbuf,"%c%c",0x00,0x00); */
  /*  addpacket(pktbuf,msgbuf,2); */

  /* ciaddr */
  memset(msgbuf,0,4);
  sprintf(msgbuf,"%c%c%c%c",ip[0],ip[1],ip[2],ip[3]);
  addpacket(pktbuf,msgbuf,4);

  /* yiaddr */
  memset(msgbuf,0,4);
  addpacket(pktbuf,msgbuf,4);

  /* siaddr */
  memset(msgbuf,0,4);
  addpacket(pktbuf,msgbuf,4);

  /* giaddr */
  sprintf(msgbuf,"%c%c%c%c",gw[0],gw[1],gw[2],gw[3]);
  addpacket(pktbuf,msgbuf,4);

  /* chaddr */
  sprintf(msgbuf,"%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c",
          hw[0],hw[1],hw[2],hw[3],hw[4],hw[5],hw[6],hw[7],
          hw[8],hw[9],hw[10],hw[11],hw[12],hw[13],hw[14],hw[15]);
  addpacket(pktbuf,msgbuf,16);

  /* sname */
  memset(msgbuf,0,64);
  addpacket(pktbuf,msgbuf,64);

  /* file */
  memset(msgbuf,0,128);
  addpacket(pktbuf,msgbuf,128);

  /* options */
  {
    /* cookie */
    sprintf(msgbuf,"%c%c%c%c",99,130,83,99);
    addpacket(pktbuf,msgbuf,4);

    /* dhcp-type */
    sprintf(msgbuf,"%c%c%c",53,1,type);
    addpacket(pktbuf,msgbuf,3);

    /* Not for inform or decline or leasequery */
    if (type!=8 && type!=4 && type!=13 && type!=10)
      {
        /* requested IP address */
        if (opt50)
          {
            sprintf(msgbuf,"%c%c%c%c%c%c",50,4,ip50[0],ip50[1],ip50[2],ip50[3]);
            addpacket(pktbuf,msgbuf,6);
          }

        /* Option 60 */
        if (opt60)
          {
            sprintf(msgbuf,"%c%c%s",60,10,opt60);
            addpacket(pktbuf,msgbuf,12);
          }

        /* Option 82 */
        if ((opt82 != "00:00:00:00:00:00") && opt82 )
          {
            sprintf(msgbuf,"%c%c%c%c%c%c%c%c%c%c",82,8,2,6,opt82mac[0],opt82mac[1],opt82mac[2],opt82mac[3],opt82mac[4],opt82mac[5]);
            addpacket(pktbuf,msgbuf,10);
          }

        /* server-identifier */
        if (serveridentifier[0])
          {
            sprintf(msgbuf,"%c%c%c%c%c%c",54,4,
                    serveridentifier[0],serveridentifier[1],
                    serveridentifier[2],serveridentifier[3]);
            addpacket(pktbuf,msgbuf,6);
          }
      }

//    /* client-identifier */
//    /* removed in version 1.4d because of leasequery issue cnr7 */
//    sprintf(msgbuf,"%c%c%c%c%c%c%c%c%c",61,7,1,
//    hw[0],hw[1],hw[2],hw[3],hw[4],hw[5]);
//    addpacket(pktbuf,msgbuf,9);

//    /* parameter request list */
//    if (type==8)
//      {
//        sprintf(msgbuf,"%c%c%c",55,1,1);
//        addpacket(pktbuf,msgbuf,3);
//      }

//
    /* parameter request list for leasequery and inform */
    if (request==0 && discover==0 && (type==13 || type==10 || type==8))
      {
        sprintf(msgbuf,"%c%c%c%c%c%c",55,4,51,60,61,82);
        addpacket(pktbuf,msgbuf,6);
      }
//

    /* end of options */
    sprintf(msgbuf,"%c",255);
    addpacket(pktbuf,msgbuf,1);
  }

// show packet
  dhcp_dump(pktbuf,offset);

// send to dhcp socket
  sendto(dhcp_socket,pktbuf,offset,0,(struct sockaddr *)&dhcp_to,sizeof(dhcp_to));

  offset=0;
}


////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////


int dhcp_read(void)
{
  unsigned char msgbuf[BUF_SIZ];
  struct sockaddr_in fromsock;
  socklen_t fromlen=sizeof(fromsock);
  int addr;
  int i;

  i=recvfrom(dhcp_socket,msgbuf,BUF_SIZ,0,(struct sockaddr *)&fromsock,&fromlen);
  addr=ntohl(fromsock.sin_addr.s_addr);

  if (VERBOSE)
    printf("\n---------------------------------------------------------------------------\n\n");
  if (!quiet)
    {
      printf( "Got answer from: %d.%d.%d.%d\n",
              ( addr >> 24 ) & 0xFF, ( addr >> 16 ) & 0xFF,
              ( addr >>  8 ) & 0xFF, ( addr       ) & 0xFF
            );
    }

  if (_serveripaddress!=addr)
    {
      if (!quiet)
        fprintf(stderr,"received from %d.%d.%d.%d, expected from %d.%d.%d.%d\n",
                ( addr >> 24 ) & 0xFF, ( addr >> 16 ) & 0xFF,
                ( addr >>  8 ) & 0xFF, ( addr       ) & 0xFF,
                ( _serveripaddress >> 24 )&0xFF,(_serveripaddress >> 16 )&0xFF,
                ( _serveripaddress >>  8 )&0xFF,(_serveripaddress       )&0xFF
               );
      return 0;

    }


  dhcp_dump(msgbuf,i);
  return 1;
}


////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////


void dhcp_dump(unsigned char *buffer,int size)
{
  int j,i,a;

  if (VERBOSE)
    printf("packet %d bytes\n",size);

  if (!VERBOSE)
    return;

  //
  // Are you sure you want to see this? Try dhcpdump, which is better
  // suited for this kind of work... See http://www.mavetju.org
  //
  /*
  j=0;
  while (j<size) {
    printf("%02x ",buffer[j]);
    if (j%16==15) printf("\n");
    j++;
  }
  printf("\n");
  */

  printf("\nnop: %d\n",buffer[0]);
  printf("htype: %d\n",buffer[1]);
  printf("hlen: %d\n",buffer[2]);
  printf("hops: %d\n",buffer[3]);
  printf("xid: %02x%02x%02x%02x\n",
         buffer[4],buffer[5],buffer[6],buffer[7]);
  printf("secs: %d\n",255*buffer[8]+buffer[9]);
  printf("flags: %x\n",255*buffer[10]+buffer[11]);

  if (buffer[12]==0 && buffer[13]==0 && buffer[14]==0 && buffer[15]==0)
    {
      printf("ciaddr: no entry found\n");
    }
  else
    {
      printf("ciaddr: %d.%d.%d.%d\n",
             buffer[12],buffer[13],buffer[14],buffer[15]);
    }
//    printf("ciaddr: %d.%d.%d.%d\n",
//      buffer[12],buffer[13],buffer[14],buffer[15]);

  printf("yiaddr: %d.%d.%d.%d\n",
         buffer[16],buffer[17],buffer[18],buffer[19]);
  printf("siaddr: %d.%d.%d.%d\n",
         buffer[20],buffer[21],buffer[22],buffer[23]);
  printf("giaddr: %d.%d.%d.%d\n",
         buffer[24],buffer[25],buffer[26],buffer[27]);

  if (buffer[2]==0)
    {
      printf("chaddr: no entry found\n");
    }
  else
    {
      if (buffer[2]==6)
        {
          printf("chaddr: %02x:%02x:%02x:%02x:%02x:%02x\n",
                 buffer[28],buffer[29],buffer[30],buffer[31],
                 buffer[32],buffer[33]);
        }
      else
        {
          printf("chaddr: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
                 buffer[28],buffer[29],buffer[30],buffer[31],
                 buffer[32],buffer[33],buffer[34],buffer[35],
                 buffer[36],buffer[37],buffer[38],buffer[39],
                 buffer[40],buffer[41],buffer[42],buffer[43]);
        }
    }

//    printf("chaddr: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
//      buffer[28],buffer[29],buffer[30],buffer[31],
//      buffer[32],buffer[33],buffer[34],buffer[35],
//      buffer[36],buffer[37],buffer[38],buffer[39],
//      buffer[40],buffer[41],buffer[42],buffer[43]);

  printf("sname : %s\n",buffer+44);
  printf("fname : %s\n",buffer+108);

  j=236;
  j+=4; /* cookie */
  while (j<size && buffer[j]!=255)
    {
      printf("option %d %s\n",buffer[j],dhcp_options[buffer[j]]);
      switch (buffer[j])
        {
        case 1:
          printf("\tSubnet mask: %d.%d.%d.%d\n",
                 buffer[j+2],buffer[j+3],buffer[j+4],buffer[j+5]);
          break;
        case 2:
          printf("\tTime Offset: ");
          printTime32(buffer+j+2);
          printf("\n");
          break;
        case 3:
          printf("\tRouter: %d.%d.%d.%d\n",
                 buffer[j+2],buffer[j+3],buffer[j+4],buffer[j+5]);
          break;
        case 4:
          printf("\tTime-server: ");
          for (i=0; i<buffer[j+1]/4; i++)
            {
              if (i!=0) printf(",");
              printf("%d.%d.%d.%d",buffer[j+2+i*4],buffer[j+3+i*4],buffer[j+4+i*4],buffer[j+5+i*4]);
            }
          printf("\n");
          break;
        case 5:
          printf("\tName-server: ");
          for (i=0; i<buffer[j+1]/4; i++)
            {
              if (i!=0) printf(",");
              printf("%d.%d.%d.%d",buffer[j+2+i*4],buffer[j+3+i*4],buffer[j+4+i*4],buffer[j+5+i*4]);
            }
          printf("\n");
          break;
        case 6:
          printf("\tDomain-name-server: ");
          for (i=0; i<buffer[j+1]/4; i++)
            {
              if (i!=0) printf(",");
              printf("%d.%d.%d.%d",buffer[j+2+i*4],buffer[j+3+i*4],buffer[j+4+i*4],buffer[j+5+i*4]);
            }
          printf("\n");
          break;
        case 7:
          printf("\tLog-server: ");
          for (i=0; i<buffer[j+1]/4; i++)
            {
              if (i!=0) printf(",");
              printf("%d.%d.%d.%d",buffer[j+2+i*4],buffer[j+3+i*4],buffer[j+4+i*4],buffer[j+5+i*4]);
            }
          printf("\n");
          break;
        case 15:
          printf("\tDomain-name: ");
          for (i=0; i<buffer[j+1]; i++)
            {
              printf("%c",buffer[j+2+i]);
            }
          printf("\n");
          break;
        case 42:
          printf("\tntp-server: %d.%d.%d.%d\n",
                 buffer[j+2],buffer[j+3],buffer[j+4],buffer[j+5]);
          break;
// option 43 disabled for unknown reason?
//        case 43:
//            printf("\tVendor Specific Information: ");
//            for (i=0;i<buffer[j+1];i++) {
//              printf("%c",buffer[j+2+i]);
//            }
//            printf("\n");
//          break;
        case 50:
          printf("\tRequested IP address: %d.%d.%d.%d\n",
                 buffer[j+2],buffer[j+3],buffer[j+4],buffer[j+5]);
          break;
        case 51:
          printf("\tIP address leasetime: ");
          printTime32(buffer+j+2);
          printf("\n");
          break;
        case 53:
          printf("\tDHCP message type: %d (%s)\n",
                 buffer[j+2],dhcp_message_types[buffer[j+2]]);
          break;
        case 54:
          memcpy(serveridentifier,buffer+j+2,4);
          printf("\tServer identifier: %d.%d.%d.%d\n",
                 serveridentifier[0],serveridentifier[1],
                 serveridentifier[2],serveridentifier[3]);
          break;
// Parameter Request List
        case 55:
//          printf("\tParameter Request List: \n");
          for (i=0; i<buffer[j+1]; i++)
            {
                printf("\toption %d %s\n",buffer[j+2+i],dhcp_options[buffer[j+2+i]]);
            }
          printf("\n");
          break;
        case 60:
          printf("\tVendor Class Identifier: ");
          for (i=0; i<buffer[j+1]; i++)
            {
              printf("%c",buffer[j+2+i]);
            }
          printf("\n");
          break;
        case 61:
          printf("\tClient identifier: %02x%02x%02x%02x%02x%02x\n",
                 buffer[j+2],buffer[j+3],buffer[j+4],
                 buffer[j+5],buffer[j+6],buffer[j+7]);
          break;
        case 66:
          printf("\ttftp-server: ");
          for (i=0; i<buffer[j+1]; i++)
            {
              printf("%c",buffer[j+2+i]);
            }
          printf("\n");
          break;
        case 67:
          printf("\tboot-file: ");
          for (i=0; i<buffer[j+1]; i++)
            {
              printf("%c",buffer[j+2+i]);
            }
          printf("\n");
          break;
// client-last-transaction time
//        case 91:
//          printf("\tclient-last-transaction-time: ");
//          printTime32(buffer+j+2);
//          printf("\n");
//          break;
        case 122:
          printf("\tCablelabs-client-configuration: \n");
          a=2;
          while (a<=buffer[j+1])
            {
              switch (buffer[j+a])
                {
                case 1:
                  printf("\t\tPrimary DHCP: ");
                  for (i=0; i<buffer[j+a+1]; i++)
                    {
                      if (i==0) printf("%d",buffer[j+a+2]);
                      else printf(".%d",buffer[j+a+2+i]);
                    }
                  printf("\n");
                  break;
                case 2:
                  printf("\t\tSecondary DHCP: ");
                  for (i=0; i<buffer[j+a+1]; i++)
                    {
                      if (i==0) printf("%d",buffer[j+a+2]);
                      else printf(":%d",buffer[j+a+2+i]);
                    }
                  printf("\n");
                  break;
                case 6:
                  printf("\t\tKerberos REALM: ");
                  for (i=0; i<buffer[j+a+1]; i++)
                    {
                      if (i==0) printf("%c",buffer[j+a+2]);
                      else printf("%c",buffer[j+a+2+i]);
                    }
                  printf("\n");
                }
              a+=buffer[j+a+1]+2;
            }
          break;
        case 161:
          printf("\tAssociated IPs: ");
          for (i=0; i<buffer[j+1]/4; i++)
            {
              if (i!=0) printf(",");
              printf("%d.%d.%d.%d",buffer[j+2+i*4],buffer[j+3+i*4],buffer[j+4+i*4],buffer[j+5+i*4]);
            }
          printf("\n");
          break;
        case 162:
          printf("\tHostname: ");
          for (i=0; i<buffer[j+1]; i++)
            {
              printf("%c",buffer[j+2+i]);
            }
          printf("\n");
          break;
        case 163:
          printf("\tLast transaction ");
          printTime32(buffer+j+2);
          printf(" ago\n");
          break;
        case 177:
          printf("\tPacketCable: ");
          a=2;
          while (a<=buffer[j+1])
            {
              switch (buffer[j+a])
                {
                case 1:
                  printf("\t\tPrimary DHCP: ");
                  for (i=0; i<buffer[j+a+1]; i++)
                    {
                      if (i==0) printf("%d",buffer[j+a+2]);
                      else printf(".%d",buffer[j+a+2+i]);
                    }
                  printf("\n");
                  break;
                case 2:
                  printf("\t\tSecondary DHCP: ");
                  for (i=0; i<buffer[j+a+1]; i++)
                    {
                      if (i==0) printf("%d",buffer[j+a+2]);
                      else printf(":%d",buffer[j+a+2+i]);
                    }
                  printf("\n");
                  break;
                case 6:
                  printf("\t\tKerberos REALM: ");
                  for (i=0; i<buffer[j+a+1]; i++)
                    {
                      if (i==0) printf("%c",buffer[j+a+2]);
                      else printf("%c",buffer[j+a+2+i]);
                    }
                  printf("\n");
                }
              a+=buffer[j+a+1]+2;
            }
          break;
        case 82:
          a=2;
          while (a<=buffer[j+1])
            {
              switch (buffer[j+a])
                {
                case 1:
                  printf("\tAgent Circuit ID: ");
                  for (i=0; i<buffer[j+a+1]; i++)
                    {
                      if (i==0) printf("%02x",buffer[j+a+2]);
                      else printf(":%02x",buffer[j+a+2+i]);
                    }
                  printf("\n");
                  break;
                case 2:
                  printf("\tAgent Remote ID: ");
                  for (i=0; i<buffer[j+a+1]; i++)
                    {
                      if (i==0) printf("%02x",buffer[j+a+2]);
                      else printf(":%02x",buffer[j+a+2+i]);
                    }
                  printf("\n");
                }
              a+=buffer[j+a+1]+2;
            }
        }
      /*
      // This might go wrong if a mallformed packet is received.
      // Maybe from a bogus server which is instructed to reply
      // with invalid data and thus causing an exploit.
      // My head hurts... but I think it's solved by the checking
      // for j<size at the begin of the while-loop.
      */
      j+=buffer[j+1]+2;
    }
}


void dhcp_close(void)
{
  close(dhcp_socket);
}
