

#include "trcServer.h"

BOOLEAN validate_url(char *url) 
{
    
	int count, ascii;
  	for(count = 0;count < strlen(url) ; count++) 
	{
    		ascii =  url[count];
   		if ( !((ascii >= 48 && ascii <= 57) || ( ascii == 46 ) || (ascii >= 65 && ascii <= 97 ) || (ascii >= 97 && ascii <= 122))) 
       			return FALSE;
  	}
   	return TRUE;
}


// A generic logfile which can be extended and easily understood

void writeLogFile(int logtype , const char *ipAddress , const char *time) 
{

	pthread_mutex_lock( &lockLog );
  	FILE *outFile = fopen("msglog.txt","a+");
  	string logMsg ;
  	char mesg[SIZE];
  	setZeroMemory(mesg,SIZE);  
  
  	if(outFile != NULL ) 
	{
     		switch(logtype) 
		{

		       case NEWCONNECT: 
				    sprintf(mesg, " NEWCONNECT : User with IP= %s now connects to server :\n",ipAddress);
				    break;
		       case MAX_USERS:
				    sprintf(mesg, " MAX_USERS :Server can't accept more users , exceeded the limit:\n");
				    break;
		       case DISCONNECT:
				    sprintf(mesg, " DISCONNECT :User with IP= %s disconnects : \n",ipAddress);
				    break;
		       case WRONG_URL:
				    sprintf(mesg, " WRONG_URL :User with IP= %s enters wrong format in IP Address :\n",ipAddress);
				    break;
		       case SUCCESS:
				    sprintf(mesg, " SUCCESS :User with IP= %s executes successfully for traceroute :\n",ipAddress);
				    break;
		       case STRICT_DEST:
				   sprintf(mesg, " STRICT_DEST :User with IP= %s violated strict_dest conditions :\n",ipAddress);
				   break;
		       case UNSUCCESS:
				   sprintf(mesg, " UNSUCCESS :User with IP= %s  failed to execute successfully for traceroute :\n",ipAddress);
				   break;
		       case TRTOME:
				  sprintf(mesg, " TRTOME :User with IP= %s  executes [traceroute me] :\n",ipAddress);
				   break;
		       case INVALID_CMD:
				  sprintf(mesg, " INVALID_CMD :User with IP= %s  executes invalid command:\n",ipAddress);
				   break;
		       case CMD_HELP:
				   sprintf(mesg, " CMD_HELP :User with IP= %s  executes [HELP] command:\n",ipAddress);
				   break;
		       case SOCKTIMEOUT:
				   sprintf(mesg, " SOCKTIMEOUT :User with IP= %s  has timed out So closing the connection:\n",ipAddress);
				   break;
			case TRFILE:
				   sprintf(mesg, " TRFILE :User with IP= %s  has executed traceroute command from file:\n",ipAddress);
				   break;
			case RATE_FILE:
				    sprintf(mesg, " RATE_FILE:User with IP= %s  has exceeded time while reading from file :\n",ipAddress);
				   break;
			case RATE:
				   sprintf(mesg, " RATE:User with IP= %s  has exceeded rate limiting while executing :\n",ipAddress);
				   break;
		       //place for other errors
		}
  	}
 	logMsg = logMsg + time + mesg;
 	fputs(logMsg.c_str(),outFile);
 	fclose(outFile);
 	pthread_mutex_unlock( &lockLog );
}

void showUsage() 
{

  	//write all options for traceroute here in cout .
  	//before calling this function , make sure u do dup2(sockfd,1)
        //printf(" in show usage\n");	
	cout<<"\n------------------------------------------------------------------------------------------------------------------------\n";
	cout<<"The following commands are supported by the server:\n";
	cout<<"1. traceroute [destination machine]: destination machine can either be an IP address or a DNS host name.\n";
	cout<<"2. traceroute [file name]: The specified file should be present in the Server's local directory and it must contain one or more commands in the format 'traceroute [destination machine]'.\n";
	cout<<"3. traceroute me: executes traceroute using client's hostname/IP address.\n";
	cout<<"4. help: displays list of commands supported by server. \n";
	cout<<"5. quit: closes the connection. \n";
	cout<<"\n------------------------------------------------------------------------------------------------------------------------\n";

}


bool checkExecTime(struct timeval &old) 
{ 
       struct timeval current;
       gettimeofday(&current,NULL);
       if ( current.tv_sec > old.tv_sec )
           return true;
       return false;
}