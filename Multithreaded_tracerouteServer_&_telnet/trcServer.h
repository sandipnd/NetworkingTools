
#include<iostream>
#include <fstream>
#include<stdlib.h>
#include<sys/types.h>
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
#include<string>
#include<signal.h>
#include<sys/unistd.h>
#include<netdb.h>
#include<sys/time.h>

#define MAX_U_LIMIT 1200
#define SIZE 1024
#define BACKLOG 20
#define ERROR -1
#define MAXCMD 10
#define setZeroMemory(dest,length)  memset((dest),0,length);
#define SIZEOF(sockaddr_in) sizeof(struct sockaddr_in)
#define MAX_THREAD 1200
#define SET 1
#define UNSET 0

using namespace std;

enum BOOLEAN 
{
    FALSE = 0 ,
    TRUE = 1
}; 

enum  defaultValue 
{ 
    PORT = 1216, 
    MAXUSER = 2 , 
    RATEREQUEST = 4 , 
    SECONDS = 60 ,
    DSTFLAG = 0
 };

enum logType 
{
    RATE = 0,
    MAX_USERS = 1,
    STRICT_DEST = 2,
    WRONG_URL = 3,
    DISCONNECT = 5,
    NEWCONNECT = 6,
    SUCCESS = 7,
    UNSUCCESS = 8,
    FILE_READ = 9,
    TRTOME = 10,
    INVALID_CMD = 11,
    CMD_HELP = 12,
    SOCKTIMEOUT = 13,
    TRFILE = 14,
    RATE_FILE = 15
 };


class tracert 
{
  private :
    int portNumber;
    int numRequest;
    int numSeconds;
    int maxUsers;
    int dest;
   public :
    tracert()  { portNumber = PORT ; maxUsers = MAXUSER ; numRequest  = RATEREQUEST ; numSeconds = SECONDS; dest = DSTFLAG; }
    void setMaxUser(int maxUser ) { maxUsers = maxUser ; }
    void setPort(int port) { portNumber = port ;}
    void setRateNum ( int num ) { numRequest = num; }
    void setRateSec ( int seconds ) { numSeconds = seconds; }
    void setDest(int flag ) { dest = flag; }
    int getDest ()          { return dest; }
    int getPort ()          { return portNumber; };
    int getMaxUser()        { return maxUsers; };
    int getRateNum()        { return numRequest; }
    int getRateSec()        { return numSeconds; } 
    ~tracert() { }
};

extern class tracert trCmd;
extern int numberOfUser ;
extern pthread_mutex_t lockCounter , lockLog;
void cleanup(int *);
char *calculateTime(char []);
void* serveRequest(void *arg );
void writeLogFile(int , const char *, const char *);
BOOLEAN validate_url(char *url);
void showUsage();
bool checkExecTime(struct timeval &);



