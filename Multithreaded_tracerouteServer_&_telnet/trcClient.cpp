
#include <sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <sys/time.h>
#include <errno.h>
#include <stdio.h>
#include<stdlib.h>
#include<string.h>
#include<iostream>
#include<assert.h>
#include<netdb.h>

#define SIZE 1024
#define setZeroMemory(dest,length)  memset((dest),0,length);

using namespace std;

typedef struct parameters 
{
  int port;
  char ipAddress[SIZE];
}parameters;

parameters param;


void setParam(char *argv[]) 
{ 
   param.port = atoi(argv[2]);
   struct hostent *hostname;
   hostname=gethostbyname(argv[1]);
   if( hostname == NULL ) 
      exit(1);
   cout << hostname->h_name;
   memcpy(param.ipAddress,hostname->h_name,strlen(hostname->h_name)+1); 
}


int main(int argc, char *argv[])
{
    int clientfd, cnt,connectStatus , selectStatus , nopen, dataLen;
    struct sockaddr_in  serv_addr;
    char buffer[SIZE];
    fd_set readclientfds;                            
    struct timeval tv;
    tv.tv_sec = 30 ; //as 30 sec is time out
    tv.tv_usec = 0; 

    if ( argc < 2 ) {
        cerr << "Number of arguments less than 2: option is ./client server_name <port_number>\n";
        exit(1);
     }
    setParam(argv);
    setZeroMemory(&serv_addr,sizeof (serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(param.ipAddress);
    serv_addr.sin_port = htons(param.port);

    clientfd = socket(AF_INET, SOCK_STREAM, 0);
    assert(clientfd > 0 && "socket is unable to execute\n");
        
    if (fcntl(clientfd, F_SETFL, FNONBLOCK) < 0)
        exit(1);
    connectStatus = connect(clientfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
   // assert(connectStatus == 0  && "Unable to connect \n");    


  
  while (true) 
  {
	FD_ZERO(&readclientfds);
 	FD_SET(0, &readclientfds);
  	FD_SET(clientfd, &readclientfds);
 
    	selectStatus = select(clientfd+1, &readclientfds, NULL, NULL, NULL);
    	assert(selectStatus > 0  && "select is unsuccessful\n");

    	if (FD_ISSET(0, &readclientfds)) 
	{
      		dataLen = read(0, buffer, SIZE);
      
      		if (dataLen == 0) 
		{
        		break;
      		} 
		else 
		{       
        		send(clientfd,buffer,dataLen+1,MSG_DONTWAIT); // telnet send  MSG_OOB request
      		}
    	} 
	else if (FD_ISSET(clientfd, &readclientfds)) 
	{
      		dataLen = read(clientfd, buffer, SIZE);
      		if (dataLen == 0) 
		{
		        break;
		} 
		else 
		{
		        write(1, buffer, dataLen);
		}
    	}
  }
  close(0);
  close(clientfd);
}
