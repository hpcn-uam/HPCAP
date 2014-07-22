/* fpont 12/99   */
/* pont.net      */
/* mcastServer.c */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h> /* close */

#define SERVER_PORT 1500
#define MAX_MSG 100

int main(int argc, char *argv[]) {

  int sd, rc, n, cliLen;
  struct ip_mreq mreq;
  struct sockaddr_in cliAddr, servAddr;
  struct in_addr mcastAddr;
  struct hostent *h;
  char msg[MAX_MSG];

  if(argc!=2) {
    printf("usage : %s <mcast address>\n",argv[0]);
    exit(0);
  }

  /* get mcast address to listen to */
  h=gethostbyname(argv[1]);
  if(h==NULL) {
    printf("%s : unknown group '%s'\n",argv[0],argv[1]);
    exit(1);
  }
  
  memcpy(&mcastAddr, h->h_addr_list[0],h->h_length);
  
  /* check given address is multicast */
  if(!IN_MULTICAST(ntohl(mcastAddr.s_addr))) {
    printf("%s : given address '%s' is not multicast\n",argv[0],
	   inet_ntoa(mcastAddr));
    exit(1);
  }

  /* create socket */
  sd = socket(AF_INET,SOCK_DGRAM,0);
  if(sd<0) {
    printf("%s : cannot create socket\n",argv[0]);
    exit(1);
  }

  /* bind port */
  servAddr.sin_family=AF_INET;
  servAddr.sin_addr.s_addr=htonl(INADDR_ANY);
  servAddr.sin_port=htons(SERVER_PORT);  
  if(bind(sd,(struct sockaddr *) &servAddr, sizeof(servAddr))<0) {
    printf("%s : cannot bind port %d \n",argv[0],SERVER_PORT);
    exit(1);
  }

  /* join multicast group */
  mreq.imr_multiaddr.s_addr=mcastAddr.s_addr;
  mreq.imr_interface.s_addr=htonl(INADDR_ANY);
  
  rc = setsockopt(sd,IPPROTO_IP,IP_ADD_MEMBERSHIP,
		  (void *) &mreq, sizeof(mreq));
  if(rc<0) {
    printf("%s : cannot join multicast group '%s'",argv[0],
	   inet_ntoa(mcastAddr));
    exit(1);
  }
  else {
    printf("%s : listening to mgroup %s:%d\n",
	   argv[0],inet_ntoa(mcastAddr), SERVER_PORT);
  

    /* infinite server loop */
    while(1) {
      cliLen=sizeof(cliAddr);
      n = recvfrom(sd,msg,MAX_MSG,0,(struct sockaddr *) &cliAddr,&cliLen);
      if(n<n) {
	printf("%s : cannot receive data\n",argv[0]);
	continue;
      }

      printf("%s : from %s:%d on %s : %s\n",argv[0],
	     inet_ntoa(cliAddr.sin_addr),ntohs(cliAddr.sin_port),
	     argv[1],
	     msg);
    }/* end of infinite server loop */

  }

return 0;

}
  

  
