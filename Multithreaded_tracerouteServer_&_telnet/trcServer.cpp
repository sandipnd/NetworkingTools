

#include "trcServer.h"

pthread_mutex_t lockCounter =  PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t lockLog     =  PTHREAD_MUTEX_INITIALIZER;

int numberOfUser;
class tracert trCmd;
volatile int timerFlag = SET;
pthread_t currentThreadId; 


void *get_in_addr(struct sockaddr *sa)
{
    return &(((struct sockaddr_in*)sa)->sin_addr);
}

void catch_signal(int signal) {
  
 return;
  
}

int main(int argc, char *argv[])
{
	int sockFd, portNum, newSockFd;
  	struct sockaddr_in serverAddr, clientAddr;
  	socklen_t clientLen;
  	char mesg[SIZE] , timeBuffer[32] , *tempTime;
	pthread_t thread[MAX_THREAD];
	int status , returnStatus;
        int trueRes = 1; 
        int c , number , option_index , j;
        string logNote;
        int stdoutBkup = dup(STDOUT_FILENO);
       
        static struct option options[] = {
    						{"help", no_argument, NULL, 'h'},
    						{"port", required_argument, NULL, 'p'},
    						{"max_user", required_argument, NULL, 'm'},
    						{"dest", required_argument, NULL, 'd'},
    						{"rate_seconds",required_argument,NULL,'r'},
    						{"rate_user",required_argument,NULL,'u'}
   					};
	int threadCount;
	
	while ( (c = getopt_long_only(argc, argv,"h:p:m:d:r:u:", options, &option_index)) >= 0) 
	{
        	switch(c) 
		{

                        case 'h':
                                  
                                 cout << "Usage Information\n";
				 cout << "./tracerouteServer -p [#port] -m [#max_users] -d [ strict_dest] -u [#commands] -r [#seconds] \n";
                                 exit(EXIT_SUCCESS);
                                 break;
			case 'm':
		   		number = atoi(optarg);
		   		if (number <= 0  || number > (MAX_U_LIMIT - 1)) 
				{
		     			cout << "argument for max users is invalid, traceroute server accepts 1-15. Now server can accept only 2 users which is the default value. \n";
		     			trCmd.setMaxUser(MAXUSER);
		   		}  
				else  
				{
		     			trCmd.setMaxUser(number);
		   		}
		   		break;
			case 'p':
		   		number  = atoi(optarg);
		   		if (number <= 1025 || number > 65536 ) 
				{
		     			cout << "\nargument for Port is invalid , traceroute server accepts port numbers in the range 1025 to 65536\n";
		     			trCmd.setPort(PORT);
		   		}  
				else  
				{
		      			trCmd.setPort(number);
		   		}
		   		break;
		 	case 'r':
                                
		   		number  = atoi(optarg);                  
                                if (number <= 0 ) 
				{
		     			cout << "argument for rate Seconds is invalid , we are taking only default now";
		     			trCmd.setRateSec(SECONDS);
		   		}  
				else  
				{ 
		   		        trCmd.setRateSec(number);
                                }
		   		break;

		 	case 'u':
		   		number  = atoi(optarg);
		   		if (number <= 0 ) 
				{
		     			cout << "argument for rate User is invalid , we are taking only default now";
		     			trCmd.setRateNum(RATEREQUEST);
		   		}  
				else  
				{
		     			trCmd.setRateNum(number);
		   		}
		   		break;
			case 'd' :
		    		number = atoi(optarg);
		    		if( number != 0 && number != 1 ) 
		      			trCmd.setDest(DSTFLAG);
		    		else
		       			trCmd.setDest(number);
		    		break;
	      		default:
				cout << "invalid options";
				break;
	      	}   
	} 

       	sockFd = socket(AF_INET,SOCK_STREAM, 0);
        assert(sockFd != ERROR && "Error : socket open failed");
        
        int statusSock = setsockopt( sockFd, SOL_SOCKET, (SO_REUSEADDR), &trueRes, sizeof(int) );
        assert(statusSock >= 0 && "setsockopt failed\n");        
        
        setZeroMemory((char *) &serverAddr, SIZEOF(sockaddr_in));
  	serverAddr.sin_family = AF_INET;
  	serverAddr.sin_addr.s_addr = INADDR_ANY;
  	serverAddr.sin_port = htons(trCmd.getPort());

	returnStatus = bind(sockFd,(struct sockaddr *) &serverAddr, SIZEOF(sockaddr_in));
        assert(returnStatus != ERROR && " ERROR on binding : Bind in use");
  	
  	returnStatus = listen(sockFd,BACKLOG);
        assert(returnStatus != ERROR && " ERROR on Listen: Listen failed");
  	clientLen = sizeof(struct sockaddr_in);
        numberOfUser = 0;
	threadCount=0;
        int users = trCmd.getMaxUser();
       
  	while(true) {
    	        
  		newSockFd = accept(sockFd, (struct sockaddr *) &clientAddr, &clientLen);
		if ( newSockFd == ERROR ) {
                    perror("ERROR : using accept . failed to accept connection\n");
                    break;
                }
               if ( numberOfUser > trCmd.getMaxUser() -1 ) 
		{       
                        setZeroMemory(mesg,SIZE);
			dup2(newSockFd, STDOUT_FILENO);
			cout<<"Server is busy serving other clients and it can not handle any new requests\n";
                        dup2(stdoutBkup,STDOUT_FILENO); 
			//close(newSockFd);
                       	writeLogFile(MAX_USERS,NULL,calculateTime(timeBuffer));
                        close(newSockFd);
                        logNote = "";
                        continue;
                } 
		status = pthread_create(&thread[threadCount++], 0,  serveRequest, &newSockFd);
                assert((status == 0) && "Thread Creation Falied\n");
		if(threadCount == MAX_THREAD -1) {
                        threadCount = 0;   
		}	   	
  	}
  	close(sockFd);
  	return 0;
}

void* serveRequest(void* arg ) 
{

        pthread_mutex_lock(&lockCounter);
   		numberOfUser++;
 	pthread_mutex_unlock(&lockCounter);

        //cout<<"\nNumber of user logged: "<<numberOfUser<<"\n";
 	int argSockfd = *(int *)arg;
	int *sockfd = new int[1];
	memcpy(sockfd,&argSockfd,sizeof(int));
	struct stat fileStat;
 	struct sockaddr_storage cliAddr;
 	socklen_t addr_len = sizeof(cliAddr); 
	int i , dataLen , NOFILEFLAG, strictOption = trCmd.getDest();
 	char buffer[SIZE] , *cptr , parameter[SIZE], str[SIZE] , timeBuffer[32] ;	
        int numberOfCmd = trCmd.getRateNum() ;
        int stdoutBkup = dup(STDOUT_FILENO);
        int stderrBkup = dup(STDERR_FILENO);
        int cnFlag = 1;
        string tempStr;

        struct timeval timeInactive;  
        timeInactive.tv_sec = 30;
        timeInactive.tv_usec = 0;
        int statusSock = setsockopt (sockfd[0], SOL_SOCKET, SO_RCVTIMEO, (char *)&timeInactive,sizeof(timeInactive));
        // assert(statusSock >= 0 && "setsockopt failed RCV\n");
        setsockopt (sockfd[0], SOL_SOCKET, SO_SNDTIMEO, (char *)&timeInactive,sizeof(timeInactive));

 	setZeroMemory(&cliAddr,SIZEOF(sockaddr_in));
        // to handle ip address
 	getpeername(sockfd[0], (struct sockaddr*)&cliAddr, &addr_len);
        inet_ntop(cliAddr.ss_family,get_in_addr((struct sockaddr *)&cliAddr), str, sizeof(str));
        writeLogFile(NEWCONNECT,str,calculateTime(timeBuffer));
        //printf("Client address is %s\n", str);

 	pthread_t myid = pthread_self();
        pthread_detach(pthread_self()); 

        signal(SIGALRM,catch_signal);
        alarm(trCmd.getRateSec());

        //handle rateLimit
        int rateSec = trCmd.getRateSec();
        struct timeval timeNow;
        gettimeofday(&timeNow,NULL);
        timeNow.tv_sec += rateSec; //increment current time in seconds by 
        

	while(true)
	{
 		setZeroMemory(buffer,SIZE);       
  		dataLen = recv(sockfd[0], buffer, SIZE,0);
        
        	if ( dataLen < 0 ) 
		{        
            		if ( errno == EWOULDBLOCK ) { //last error from richard stevens network programming
                	dup2(sockfd[0],STDOUT_FILENO);
                	cout << "Inactive timeout of 30 sec occured , connection closed\n";                     
 	        	dup2(stdoutBkup,STDOUT_FILENO); 
                	writeLogFile(SOCKTIMEOUT,str,calculateTime(timeBuffer));
                	cleanup(sockfd);
             	}
             	else 
                	continue;
        } 
        
        if ( numberOfCmd-- <= 0 || checkExecTime(timeNow) ) 
	{
        	dup2(sockfd[0],STDOUT_FILENO);
              	cout << "You have exceeded total Number of requests or time ,request will not be accepted, press quit to close\n";                     
 	  	dup2(stdoutBkup,STDOUT_FILENO); 
          	writeLogFile(RATE,str,calculateTime(timeBuffer));
          
          	if ( strncmp(buffer,"quit",4) == 0 ) 
	  	{
             		cleanup(sockfd);
          	}
          	continue;
         } 
   	
        NOFILEFLAG = 0;
	int flag = 0;
	
	if ( strncmp(buffer,"quit",4) == 0 ) //Code to handle quit
	{       
                writeLogFile(DISCONNECT,str,calculateTime(timeBuffer));
                cleanup(sockfd);
	}
	else if ( strncmp(buffer,"help",4) == 0 ) //code to handle help
	{       
            	cout << "\n";
            	dup2(sockfd[0],STDOUT_FILENO);
            	showUsage();                     
 	    	dup2(stdoutBkup,STDOUT_FILENO);  
            	writeLogFile(CMD_HELP,str,calculateTime(timeBuffer));       
	}
	else if ( strncmp(buffer,"traceroute",10) == 0 ) // if we encounter traceroute then process other parameter
	{
	        tempStr = "traceroute";
                int argSize = 0;
                cptr = buffer + 10 + 1; //1 for space
		argSize = dataLen - 11 - 2; // 2 for \n \0

                if ( argSize > 0 ) 
		{
		   	memcpy(parameter,cptr, argSize);
		   	parameter[argSize] ='\0';
                } 
		else 
		{
                  	parameter[0] = ' ';//case to handle only traceroute
		  	parameter[1] ='\0';
                }
		
		if(strncmp(parameter,"me",2) == 0) // for traceroute me
		{
			tempStr = tempStr +  " " + str;
                        dup2(sockfd[0],STDOUT_FILENO);
                        system(tempStr.c_str()); 
 	                dup2(stdoutBkup,STDOUT_FILENO); 
                        writeLogFile(TRTOME,str,calculateTime(timeBuffer));
		} 
		else 
		{
		       	if(stat(parameter,&fileStat) < 0) 
			{   	// we assume we dont know filename and traceroute filename is provided
			      	NOFILEFLAG = 1;   
                        }                                    // if file present we will process else not
			if (!NOFILEFLAG) 
			{
			       	ifstream sample(parameter);
                                string lines;
                                char *token = NULL, tempC[SIZE];
                           	if ( sample.is_open() ) 
				{
                             
                               		while(!sample.eof()) 
					{
						// process each line of file , tokenize each line and execute
                                  		getline(sample,lines);

                                  		if (checkExecTime(timeNow) == true ) 
						{  	
							// if timer has expired while processing the file
                                     			writeLogFile(RATE_FILE,str,calculateTime(timeBuffer));
                                     			break;
                                     			//continue
                                  		}
                                  
						memcpy(tempC,lines.c_str(),lines.length());
                                  		token = strtok(tempC," \t");
                                  		if (strcmp(token,"traceroute") != 0 )
						{
                                     			token = NULL;
				     			continue;
                                   		}
                                  		token=strtok(NULL," \t");
                                  		if ( strictOption ) 
						{
                                     			tempStr = tempStr + " " + str;
				     			dup2(sockfd[0],STDOUT_FILENO);
                                     			system(tempStr.c_str()); 
 	                             			dup2(stdoutBkup,STDOUT_FILENO); 
                                     			token = NULL;
				     			tempStr = "traceroute";
                                     			continue;
                                   		}
				   		dup2(sockfd[0],STDOUT_FILENO);
                                   		dup2(sockfd[0],STDERR_FILENO);
                                   		system(lines.c_str()); 
 	                           		dup2(stdoutBkup,STDOUT_FILENO);
                                   		dup2(stderrBkup,STDERR_FILENO);
                                   		writeLogFile(TRFILE,str,calculateTime(timeBuffer));
                                   		token = NULL;
                                	} 
                                   	sample.close();
                            }
			                      
			} 
			else 
			{
                             
                                 //checking URL validation according to project spec
				if ( validate_url(parameter) == FALSE ) 
				{
                                         dup2(sockfd[0],STDOUT_FILENO);
				         cout << "wrong format of URL or IP Address Entered ,format is traceroute IP/domainane\n";                        
                                         dup2(stdoutBkup,STDOUT_FILENO); 
                                         writeLogFile(WRONG_URL,str,calculateTime(timeBuffer));
                                }
				else 
				{ 	// run execlp or system   
                                        //cout<<"Strict Option is: "<<strictOption<<"\n";
                                        if(strictOption) 
					{
                                             	//if paramter doesnot match with IP , return and log Message
                                             	//check IP address with client  
                                             	if(strcmp(parameter,str) != 0 || strcmp(parameter,"localhost") != 0 ) 
						{
                                               		//Write Error in log
                                               		tempStr = tempStr +  " " + str;
                        		       		dup2(sockfd[0],STDOUT_FILENO);
                                               		cout << "traceroute to IP other than yours not permitted\n\n";
                                               		system(tempStr.c_str()); 
 	                                       		dup2(stdoutBkup,STDOUT_FILENO); 
                                               		writeLogFile(STRICT_DEST,str,calculateTime(timeBuffer));
                                               		continue;
                                             	}                  
                                        }
					tempStr = tempStr +  " " + parameter;
                                        dup2(sockfd[0],STDOUT_FILENO);
                                        dup2(sockfd[0],STDERR_FILENO);
                                        int exitStatus = system(tempStr.c_str()); 
 	                                dup2(stdoutBkup,STDOUT_FILENO);
                                        dup2(stderrBkup,STDERR_FILENO); //Error should be seen at client  
			        	if( exitStatus == 0) 
					{
                                            	writeLogFile(SUCCESS,str,calculateTime(timeBuffer));  
				        } 
					else 
					{
						writeLogFile(UNSUCCESS,str,calculateTime(timeBuffer));
				        }
			       }
		         } 
                    }			
		} 
		else 
		{  
			// handling the scenario for invalid command like tr
                	cout<<"\n";
                	dup2(sockfd[0],STDOUT_FILENO);
			cout<<"\n Invalid command Entered : Try Help command to see details \n";
                	dup2(stdoutBkup,STDOUT_FILENO);
                	writeLogFile(INVALID_CMD,str,calculateTime(timeBuffer));
        	}
        }	
	
}

// cleanup function is to close sockfd and release the number of User , Exit thread
void cleanup(int *sockfd) 
{

     close(sockfd[0]);
     pthread_mutex_lock(&lockCounter);
 	numberOfUser--;
     pthread_mutex_unlock(&lockCounter);   
     delete[] sockfd; 
     pthread_exit(NULL);

}

// This function calculates time
char *calculateTime(char timeBuffer[32]) 
{
        setZeroMemory(timeBuffer,32);
	time_t nowTime;
        struct tm * timeDetails;
        time ( &nowTime );
        timeDetails = localtime ( &nowTime );
        strftime (timeBuffer,32," %m/%d/%y :: %H:%M:%S " ,timeDetails);
        return timeBuffer;
}
