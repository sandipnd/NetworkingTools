

#ifndef _PORTSCANNER_H
#define _PORTSCANNER_H

#include "packets.h"
#include "opt.cpp"

#include<iostream>
#include <fstream>
#include<stdlib.h>
#include<sys/types.h>
#include <inttypes.h>
#include <sys/stat.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<stdio.h>
#include<string.h>
#include<unistd.h>
#include<error.h>
#include<errno.h> //for latest error
#include<assert.h>
#include<pthread.h>
#include<getopt.h>
#include<time.h>
#include<signal.h>
#include<sys/unistd.h>
#include<netdb.h>
#include<sys/time.h>
#include <limits.h>
#include<sys/fcntl.h>
#include<sys/ioctl.h>
#include<net/if.h>

#include<map>
//#define _DEFINE_DEPRECATED_HASH_CLASSES 0
//using namespace stdext;


using namespace std;


typedef struct args 
{
   string ip;
   int protocolNum;
   
}args;



#define NO_IP_FORMAT -1
#define setZeroMemory(dest,length)  memset((dest),0,length);
#define NUMBER_RETRANSMISSIONS 4
//#define SIZE 512
#define ABS(x) (((x)>0) ? (x) : -(x))
//response flags for checking if response
#define RESPONSE 1
#define NO_RESPONSE 0
#define WRONG_RESPONSE -1
#define INTERFACE_NAME_SIZE 512
#define IPV4_MASK 32
#define IPV6_MASK 128
#define PAYLOAD_LENGTH 512
#define MIN_THREAD_INSTANCE 1
#define TIMEOUT 5
enum ICMPRESPONSE { NO_ICMP = 0  , ICMP_UNREACHABLE =  1  , ICMP_CLOSE = 2 , ICMP_PROTO_UNREACHABLE = 3 , ICMP_REPLY = 4};
inline u_int8_t TCPOPTIONS(struct ps_tcphdr *x, u_int8_t y)  { return (x->th_flags & y); }

bool validate_url(char *url);
bool checkExecTime(struct timeval &old) ;
void createDictionary(string filename , list<string> *);
void destroyDictionary(list<string> *);
bool parseOptions(int , char ** , portScannerOpt &);
int  ipVersion(string ipAddress );
void printOptions( portScannerOpt myOpt );
void displayPacket( unsigned char *packet, int length);
void generateData(unsigned char *);
void createPseudoHeader(struct ps_pseudohdr **mypseudohdr ,struct ps_iphdr *);
void createPseudoHeader6(struct ps_pseudo6hdr **mypseudohdr ,struct ps_ip6hdr *);
uint16_t CheckSum(uint8_t *packet, size_t length);
int parseTcpHeader(unsigned char *buffer , size_t length  , string , struct ps_iphdr *, struct ps_tcphdr *, map<string,string> &);
int parseTcpHeader6(unsigned char *buffer , size_t length, string scanOptions ,struct ps_ip6hdr *oldhdr , struct ps_tcphdr *oldtcphdr, map<string,string> &p) ;
int parseIcmpHeader(unsigned char *buffer , size_t length  , void *,int);
int parseUdpHeader(unsigned char *,size_t , void *, struct ps_udphdr *,int);
void logMessage(int logtype , int port , string scanType);
char *getInterface();
void *tcpScan(void *arg);
void *udpScan(void *arg);
void *defaultScan(void *arg);

enum logType { OPEN , CLOSED , FILTERED , UNFILTERED , OPEN_FILTERED };
extern pthread_mutex_t mutexLog , lockLog , lockPort , lockProto;
extern int startPort, lastPort , gprotocolNum;
extern int portIndex, protocolThIndex;
extern map<int,map<string, string> > result;
#endif
