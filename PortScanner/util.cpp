

#include "portScanner.h"

bool validate_url(char *url) 
{    
	int count, ascii;
  	for(count = 0;count < strlen(url) ; count++) 
	{
    		ascii =  url[count];
   		if ( !((ascii >= 48 && ascii <= 57) || ( ascii == 46 ) || (ascii >= 65 && ascii <= 97 ) || (ascii >= 97 && ascii <= 122) || (ascii == 58))) 
       			return false;
  	}
   	return true;
}

void showUsage() 
{ 
	cout<<"\n------------------------------------------------------------------------------------------------------------------------\n";
	cout<<"The following commands are supported by the portScanner:\n";
	cout<<"1. --help: displays the options available to the user.\n";
	cout<<"2. -d: IP address of the machine to be scanned.\n";
	cout<<"3. -x: IP prefix to be scanned.\n";
	cout<<"4. -f: file name which contains IP addresses to be scanned. \n";
	cout<<"5. -p: port number to be scanned. \n";
	cout<<"6. -n: number of parallel threads to be used. \n";
	cout<<"7. -s: the scan to be performed like SYN, NULL, FIN, XMAS, ACK, Protocol. \n";
	cout<<"8. -r: transport protocols to be scanned. \n";
	cout<<"\n------------------------------------------------------------------------------------------------------------------------\n";
}

bool parseOptions(int argc , char *argv[] , portScannerOpt &myOpt ) 
{
   int c , number , option_index , j;
   static struct option options[] = {
    				       {"help", no_argument, NULL, 'h'},
    				       {"ports", required_argument, NULL, 'p'},
    				       {"ip", required_argument, NULL, 'd'},
    				       {"prefix", required_argument, NULL, 'x'},
    				       {"file",required_argument,NULL,'f'},
    				       {"speed-up",required_argument,NULL,'n'},
                                       {"scan",required_argument,NULL,'s'},
                                       {"protocol-range",required_argument,NULL,'r'}
   				    };
  int version;
  bool flagIp = false;           
  char *garbage = NULL;    
  while ( (c = getopt_long_only(argc, argv,"h:p:d:x:f:n:s:r:", options, &option_index)) >= 0) 
  {
        switch(c) 
	{
            case 'h':      
            	showUsage();
                return false;
                break;
            case 'p':
		//cout<<"Before setPort\n";
                myOpt.setPort(optarg);
 	        break;
            case 'd':               
                 version = ipVersion(optarg);
                 if ( version == NO_IP_FORMAT )
                 	continue;
                 flagIp = true;
                 myOpt.setDstIpAddress(optarg,version);
                 break;
            case 'x': { 
                 	string prefixIp = optarg;
                 	int posn = prefixIp.find("/");
                 	if ( posn == string::npos ) 
                      		break;
                 	string ipaddr = prefixIp.substr(0,posn);
                                 
                 	version = ipVersion(ipaddr);
                 	if ( version == NO_IP_FORMAT )
                       		break; 
                 	string mask = prefixIp.substr(posn+1,prefixIp.length());
                 	garbage = NULL;
                 	int masknet = strtol(mask.c_str(), &garbage, 0);
                                 
                 	if ( *garbage != '\0' ) 
                       		break;
                 	if ( version == IPV4  && ( masknet > IPV4_MASK || masknet < 0) )
                       		break;
                 	if ( version == IPV6  && ( masknet > IPV6_MASK || masknet < 0) )
                       		break; 
                	myOpt.setIpPrefix(ipaddr,masknet,version);
                 	flagIp = true; 
                 }
                 break;
	    case 'f':
                 myOpt.setFile(optarg);
                 flagIp = true;
                 break;
            case 'n':
                  garbage = NULL;
                  number = strtol(optarg,&garbage,0);
                  if(*garbage != '\0')
                     break;
                  myOpt.setSpeedUp(number);
                  break;
            case 's':
               	  myOpt.setScanOptions(optarg);
                  break;
            case 'r':    
		  myOpt.setProtocolRange(optarg);
                  break;
            default:
		  return false;
                  break;
            }
       	}
        
       	myOpt.setSourceIp();
       	if ( !flagIp ) 
	{
            cout << "Specify proper IP Address or Filename or Prefix\n";
            return false;
      	} 
      	return true;
}

//for debug
void printOptions( portScannerOpt myOpt ) 
{
   cout << "srcIp = " << myOpt.getSourceIp() << endl;
   cout << "version= " << myOpt.getIpVersion() << endl;
   cout << "speed = " << myOpt.getSpeedUp() << endl; 
}

bool checkExecTime(struct timeval &old) 
{ 
    struct timeval current;
    gettimeofday(&current,NULL);
    if ( current.tv_sec > old.tv_sec )
    	return true;
    return false;
}

void createDictionary(string filename,list<string> *dict ) 
{
   ifstream sample(filename.c_str());
   string lines;
   int index = 0 , pos;
   if ( sample.is_open() ) 
   {
   	while(!sample.eof()) 
   	{
	    getline(sample,lines);
            StringTokenizer strtokn(lines,",");
            string tmp = strtokn.nextToken();
            tmp = strtokn.nextToken();
       
            if ( dict[index].empty() ) 
	    {
            	dict[index].push_back(tmp);
             	tmp = strtokn.nextToken();
             	tmp = strtokn.nextToken();
             	dict[index].push_back(tmp);
             	index++; 
            } 
	    else 
	    {
            	dict[index].push_back("udp");  
            } 
      	}
        sample.close();
    }   
}

void destroyDictionary(list<string> *dict) 
{
   delete[] dict;
}


//from stevens  network book unp.h
int ipVersion ( string ipAddress ) 
{
    int getaddrStatus;
    struct addrinfo myhints,*iptype;
    char tempAddress[ipAddress.length()+1];
    strncpy(tempAddress,ipAddress.c_str(),ipAddress.length()+1);
    setZeroMemory(&myhints,sizeof(struct addrinfo));
    myhints.ai_flags = AI_CANONNAME;
    myhints.ai_family = 0;
    myhints.ai_socktype = 0;
    if ( ( getaddrStatus  = getaddrinfo(tempAddress,NULL,&myhints,&iptype)) != 0 ) 
    {
         //freeaddrinfo(iptype);
         return NO_IP_FORMAT;
    } 
  
    if ( iptype->ai_family == AF_INET ) 
    {
      	freeaddrinfo(iptype);
      	return IPV4;
    }
    if ( iptype ->ai_family == AF_INET6 ) 
    {
      	freeaddrinfo(iptype);
      	return IPV6;
    }
    
}

void displayPacket( unsigned char *packet, int length)
{
	unsigned char *pst = packet;
	cout<< "\n----- packet -------\n";
	while(length--)
	{
		printf("%.2x ", *pst);
		pst++;
	}
	cout << "\n..........displayed.......\n";
}


void generateData(unsigned char *p ) 
{
    for (int i = 0; i < DATA_SIZE; i++ )
       	p[i] = i;
}
void createPseudoHeader(struct ps_pseudohdr **mypseudohdr ,struct ps_iphdr *myiphdr ) 
{
    *mypseudohdr = (struct ps_pseudohdr *) malloc(PSEUDOHEADER_SIZE);
    (*mypseudohdr)-> saddr = myiphdr->ip_src.s_addr;
    (*mypseudohdr)->daddr = myiphdr->ip_dst.s_addr;
    (*mypseudohdr)->protocol = myiphdr->ip_p;
    (*mypseudohdr)->zero = 0;
    if ( gprotocolNum == IPPROTO_TCP )
    	(*mypseudohdr)->length = htons(TCPHEADER_SIZE); //TCPHEADER_SIZE
    else
    	(*mypseudohdr)->length = htons(UDPHEADER_SIZE); //TCPHEADER_SIZE
}
//flylib.com/books/en/2.223.1.53/1/
void createPseudoHeader6(struct ps_pseudo6hdr **mypseudohdr ,struct ps_ip6hdr *myip6hdr ) 
{
        
	*mypseudohdr = (struct ps_pseudo6hdr *) malloc(PSEUDO6HEADER_SIZE);
   	(*mypseudohdr)->ip6_src = myip6hdr->ip6_src;
    	(*mypseudohdr)->ip6_dst = myip6hdr->ip6_dst;
    	(*mypseudohdr)->next = myip6hdr->ip6_nxthdr;
        //WHERE
     	(*mypseudohdr)->zero[0] = '\0';
     	(*mypseudohdr)->zero[1] = '\0';
         //WHERE
     	(*mypseudohdr)->zero[2] = '\0';
     	if ( gprotocolNum == IPPROTO_TCP )
       	     (*mypseudohdr)->payloadlength = htons(TCPHEADER_SIZE); 
     	else
       	     (*mypseudohdr)->payloadlength = htons(UDPHEADER_SIZE); 
}

//from stevens network chapter 28
uint16_t CheckSum(uint8_t *packet, size_t length)
{
        long chkSum = 0;  
	uint16_t *tempBuff = (uint16_t *)packet;

        while(length > 1)
	{
             chkSum += *tempBuff++;
             if(chkSum & 0x80000000)  
               chkSum = (chkSum & 0xFFFF) + (chkSum >> 16);
             length -= 2;
        }

        if(length)       
             chkSum += (uint16_t) *((uint8_t *)tempBuff);
          
        while(chkSum>>16)
             chkSum = (chkSum & 0xFFFF) + (chkSum >> 16);

        return ~chkSum;
}
//-------------- Not needed ----------------------
void logMessage(int logtype , int port , string scanType) 
{
   //need to handle dictionary here
        pthread_mutex_lock( &lockLog );
  	FILE *outFile = fopen("msglog.txt","a");
  	string logMsg ;
  	char mesg[SIZE];
  	setZeroMemory(mesg,SIZE);  
  
  	if(outFile != NULL ) 
	{
     		switch(logtype) 
		{
		       case OPEN: 
				    sprintf(mesg, "port %d is OPEN ScanType =  %s \n",port,scanType.c_str());
				    break;
		       case CLOSED:
				    sprintf(mesg, "port %d is CLOSED ScanType =  %s \n",port,scanType.c_str());
				    break;
                       case FILTERED:
                                    sprintf(mesg, "port %d is FILTERED ScanType =  %s \n",port,scanType.c_str());
				    break;
                       case UNFILTERED:
                                    sprintf(mesg, "port %d is UNFILETERD ScanType =  %s \n",port,scanType.c_str());
				    break;
                       case OPEN_FILTERED:
                                    sprintf(mesg, "port %d is OPEN|FILTERED ScanType =  %s \n",port,scanType.c_str());
				    break;
		      
		}
  	}
 	logMsg = logMsg +  mesg;
 	fputs(logMsg.c_str(),outFile);
 	fclose(outFile);
 	pthread_mutex_unlock( &lockLog );
}

/*
void addtoMap(int portNum, map<string,string> p)
{
	int previousPort;
	previousPort = portNum; //ntohs(oldtcphdr->th_dport);
	result.insert(pair<int,map<string,string> >(previousPort,p));
	map<int,map<string,string> >::iterator outerIter;
	map<string,string>::iterator innerIter;
	outerIter = result.find(previousPort);
	//cout<<"\nPort:"<<previousPort<<"\n";
	for(innerIter = outerIter->second.begin(); innerIter!= outerIter->second.end(); innerIter++)
	{
		cout<<innerIter->first<<"--->"<<innerIter->second<<"\n";	
	}
	result.erase(previousPort);
}*/

int parseTcpHeader(unsigned char *buffer , size_t length, string scanOptions ,struct ps_iphdr *oldhdr , struct ps_tcphdr *oldtcphdr, map<string,string> &p) 
{
     	//case when response received
       	if(length < TCPHEADER_SIZE + IPHEADER_SIZE) 
	{
             cout << "header size is too small \n";
             return  WRONG_RESPONSE;
       	}
       	struct ps_iphdr *rcvIphdr;
       	struct ps_tcphdr *rcvTcphdr ;
       	rcvIphdr = (struct ps_iphdr *)buffer;
       
       	int ipSize = IP_HL(rcvIphdr) * 4;
       	if ( ipSize < IPHEADER_SIZE) 
	{
           cerr << "size of ip header is less than " << IPHEADER_SIZE << endl;
           return WRONG_RESPONSE;
        }
        //map<string,string> p;
      	
       	rcvTcphdr = (struct ps_tcphdr *)(buffer + IPHEADER_SIZE);
      	/* int tcpSize = TH_OFF(rcvTcphdr) *4;
       	//cout << "tcpsize " << tcpSize;
       	if ( tcpSize < TCPHEADER_SIZE) {
           cerr << "size of TCP header is less than " << TCPHEADER_SIZE << endl;
           return NO_RESPONSE;
        } */ 
         //cout << "port is : " << ntohs(rcvTcphdr->th_dport) << endl;

        if ( strcmp(inet_ntoa(oldhdr->ip_src),inet_ntoa(rcvIphdr->ip_dst)) != 0 )  
	{
               return NO_RESPONSE;
        }

        if (! (ntohs(oldtcphdr->th_sport ) == ntohs(rcvTcphdr->th_dport) && ntohs(oldtcphdr->th_dport ) == ntohs(rcvTcphdr->th_sport))) 
        {
              return NO_RESPONSE;
        }

        //check if ports are similar
        //cout << "flag is = " << ntohs(TH_RST) << " : " << ntohs(rcvTcphdr->th_flags) <<  endl;
        if( scanOptions.compare("SYN") == 0 ) 
	{
              //printf(" SYN TH_RST %d \n",rcvTcphdr->th_flags);
            if (TCPOPTIONS(rcvTcphdr,TH_SYN) == TH_SYN && TCPOPTIONS(rcvTcphdr,TH_ACK) == TH_ACK)
            { 
                //write to log parse from dictionary
                //cout << "open  SYN";
		p.insert(pair<string,string>("SYN","open"));
                getService *chkService = new getService(inet_ntoa(oldhdr->ip_dst));
                //chkService=
                char *temp = inet_ntoa(oldhdr->ip_dst);
                string Version;
                switch(ntohs(oldtcphdr->th_dport)) 
		{
                     case HTTP:
                            Version = chkService->testHTTP(); //working
			    p.insert(pair<string,string>("HTTP Version",Version));
                            break;
                     case SSH:
                            //cout << chkService->getIp();
                            Version = chkService->testSSH(); //working
			    p.insert(pair<string,string>("SSH Version",Version));
                            break; 
                     case WHOIS:         
                            Version = chkService->testWHOIS();
			    p.insert(pair<string,string>("WHOIS",Version));
                            break;
                     case SMTP:
                            Version = chkService->testSMTP();
			    p.insert(pair<string,string>("SMTP",Version));
                            break;
                     case POP3:
                            Version = chkService->testPOP3(); //working
			    p.insert(pair<string,string>("POP3",Version));
                            break;
                     case IMAP:
                            Version = chkService->testIMAP(); //working
			    p.insert(pair<string,string>("IMAP",Version));
                            break;
                     default:
                            struct servent *service= getservbyport(oldtcphdr->th_dport, "tcp");
                            if ( chkService->createConn(ntohs(oldtcphdr->th_dport)) >= 0 )  
 			    {
                                char serviceV[SIZE];
                                sprintf(serviceV,"port : %d Open for service = %s ",ntohs(oldtcphdr->th_dport),service->s_name);
				p.insert(pair<string,string>(service->s_name,string(serviceV)));
                            }
                            break;    
                }
		//addtoMap(ntohs(oldtcphdr->th_dport), p);
                delete chkService;
                return RESPONSE;
            }
             
            else if (TCPOPTIONS(rcvTcphdr,TH_RST) == TH_RST) 
	    {  
                 //cout << " SYN closed";
		 p.insert(pair<string,string>("SYN","closed"));
		 //addtoMap(ntohs(oldtcphdr->th_dport), p);
                 return RESPONSE;
            }
        } 
	else if ( scanOptions.compare("ACK") == 0 ) 
	{       
            if ( TCPOPTIONS(rcvTcphdr , TH_RST) == TH_RST) 
	    {
            	//cout << "ACK unfiltered"; //unfiltered
               
		p.insert(pair<string,string>("ACK","unfiltered"));
		//addtoMap(ntohs(oldtcphdr->th_dport), p);
                return RESPONSE;  
            }
        } 
	else if ( scanOptions.compare("NULL") == 0   || scanOptions.compare("XMAS") == 0  || scanOptions.compare("FIN") == 0)     
        {                              
            string scantype ;
	    if(scanOptions.compare("NULL") == 0)
		scantype = "NULL";
	    else if(scanOptions.compare("XMAS") == 0)
		scantype = "XMAS";
	    else if(scanOptions.compare("FIN") == 0)
		scantype = "FIN";
 	    if ( TCPOPTIONS(rcvTcphdr , TH_RST) == TH_RST) 
 	    {   
            	//cout << "NULL closed";
		p.insert(pair<string,string>(scantype ,"filtered"));
		//addtoMap(ntohs(oldtcphdr->th_dport), p);
                return RESPONSE;
            }
	} 
	return NO_RESPONSE;
}


int parseUdpHeader(unsigned char *buffer , size_t packetlength, void *oldiphdr , struct ps_udphdr *oldudphdr,int ipversion) 
{
    int IPHEADER;
    struct ps_iphdr *rcviphdr , *iphdr;
    struct ps_ip6hdr *rcvip6hdr , *ip6hdr;
    IPHEADER = ( (ipversion == 4) ? IPHEADER_SIZE:IPV6HEADER_SIZE);
    if ( packetlength < ( IPHEADER + UDPHEADER_SIZE) )
     	return NO_RESPONSE;

    if ( ipversion == IPV4) 
    {
       	iphdr = (struct ps_iphdr *)oldiphdr;
       	rcviphdr = (struct ps_iphdr *)buffer;
       	int ipSize = IP_HL(rcviphdr) * 4;
       	if ( ipSize < IPHEADER_SIZE) 
	{
            cerr << "size of ip header is less than " << IPHEADER_SIZE << endl;
            return WRONG_RESPONSE;
        } 
        if ( rcviphdr->ip_p != IPPROTO_UDP )
            return NO_RESPONSE;
        if ( strcmp(inet_ntoa(iphdr->ip_src),inet_ntoa(rcviphdr->ip_dst)) != 0 )  
	{
            //cerr << "The source Ip  of send IPheader and destIP of receive header not same";
            // return  WRONG_RESPONSE;
            return NO_RESPONSE;
        }
        if ( strcmp(inet_ntoa(iphdr->ip_dst),inet_ntoa(rcviphdr->ip_src)) != 0 )  
	{
            //cerr << "The source Ip  of send IPheader and destIP of receive header not same";
            // return  WRONG_RESPONSE;
            return NO_RESPONSE;
        }
    } 
    else 
    {
       /*do all check for IPV6
       ip6hdr = (struct ps_ip6hdr *)oldiphdr;
       rcvip6hdr = ( struct ps_ip6hdr *)buffer;
        if ( strcmp(inet_ntoa(ip6hdr->ip6_src),inet_ntoa(rcvip6hdr->ip6_dst)) != 0 )  {

              //cerr << "The source Ip  of send IPheader and destIP of receive header not same";
             // return  WRONG_RESPONSE;
               return NO_RESPONSE;
        }
       if ( strcmp(inet_ntoa(ip6hdr->ip6_dst),inet_ntoa(rcvip6hdr->ip6_src)) != 0 )  {

              //cerr << "The source Ip  of send IPheader and destIP of receive header not same";
             // return  WRONG_RESPONSE;
               return NO_RESPONSE;
        } */
    }
      
    struct ps_udphdr *rcvUdphdr;
    rcvUdphdr = (struct ps_udphdr *)(buffer + IPHEADER);
    if (! (ntohs(oldudphdr->uh_sport ) == ntohs(rcvUdphdr->uh_dport) && ntohs(oldudphdr->uh_dport ) == ntohs(rcvUdphdr->uh_sport))) 
    {
    	//cerr << "The source port and dest port doesnot match";
    	//return  WRONG_RESPONSE;
        return NO_RESPONSE;
    }
    struct servent *service= getservbyport(oldudphdr->uh_dport, "udp");
    cout << "port : " << ntohs(oldudphdr->uh_dport) <<" Open for service " << service->s_name << endl;          
    return RESPONSE;            
}

/*
 if Udp response we get its open
 */
int parseIcmpHeader(unsigned char *buffer , size_t packetlength, void *oldiphdr ,int ipversion) 
{
    int IPHEADER;
    struct ps_iphdr *rcviphdr , *iphdr;
    struct ps_ip6hdr *rcvip6hdr , *ip6hdr;
      
    IPHEADER = ( (ipversion == 4) ? IPHEADER_SIZE:IPV6HEADER_SIZE);
    // if ( packetlength < ( IPHEADER + ICMPHEADER_SIZE) )
         //return NO_ICMP;

    if ( ipversion == IPV4) 
    {
    	iphdr = (struct ps_iphdr *)oldiphdr;
       	rcviphdr = (struct ps_iphdr *)buffer;
       	int ipSize = IP_HL(rcviphdr) * 4;
       	if ( ipSize < IPHEADER_SIZE) 
	{
            cerr << "size of ip header is less than " << IPHEADER_SIZE << endl;
            return NO_ICMP;
        } 
       	if ( rcviphdr->ip_p != IPPROTO_ICMP )
            return NO_ICMP;

        if ( strcmp(inet_ntoa(iphdr->ip_src),inet_ntoa(rcviphdr->ip_dst)) != 0 )  
	{
             return NO_ICMP;
        }
        if ( strcmp(inet_ntoa(iphdr->ip_dst),inet_ntoa(rcviphdr->ip_src)) != 0 )  
	{
             return NO_ICMP;
        }
       	//cout << inet_ntoa(iphdr->ip_dst) << "src" << inet_ntoa(rcviphdr->ip_src) << "\n";
    } 
    else 
    {
       /*do all check for IPV6
       ip6hdr = (struct ps_ip6hdr *)oldiphdr;
       rcvip6hdr = ( struct ps_ip6hdr *)buffer;
       if ( strcmp(inet_ntoa(ip6hdr->ip6_src),inet_ntoa(rcvip6hdr->ip6_dst)) != 0 )  {

               return NO_ICMP;
        }
       if ( strcmp(inet_ntoa(ip6hdr->ip6_dst),inet_ntoa(rcvip6hdr->ip6_src)) != 0 )  {

               return NO_ICMP;
        } */

    }

    // check ICMP parameters
    struct icmphdr *rcvIcmp;
    rcvIcmp = (struct icmphdr *) ( buffer +IPHEADER);
      
    if ( (int)rcvIcmp->type == ICMP_ECHOREPLY )
    	return ICMP_REPLY; 
    if ((int)rcvIcmp->type == ICMP_DEST_UNREACH ) 
    {
	//WHERE
      	//cout << "icmp" << (int)rcvIcmp->code << "type\n" << (int)rcvIcmp->type ;
        int code = (int)rcvIcmp->code; 
        switch(code) 
	{
            case ICMP_PORT_UNREACH: 
                                  return ICMP_CLOSE;
                                  break;
           
           case ICMP_PROT_UNREACH:
                                  return ICMP_PROTO_UNREACHABLE;
                                  break;
           case ICMP_HOST_UNREACH:
           case ICMP_NET_ANO:
           case ICMP_HOST_ANO:
           case ICMP_PKT_FILTERED:
                                  return ICMP_UNREACHABLE;
         }
    }
    return NO_ICMP;
 }    

int parseTcpHeader6(unsigned char *buffer , size_t length, string scanOptions ,struct ps_ip6hdr *oldhdr , struct ps_tcphdr *oldtcphdr, map<string,string> &p) 
{
     	//case when response received
       	if(length < TCPHEADER_SIZE + IPV6HEADER_SIZE) 
	{
             cout << "header size is too small \n";
             return  WRONG_RESPONSE;
       	}
       	struct ps_ip6hdr *rcvIphdr;
       	struct ps_tcphdr *rcvTcphdr ;
       	rcvIphdr = (struct ps_ip6hdr *)buffer;
        char stripaddr[INET6_ADDRSTRLEN];
       
        //map<string,string> p;
      	
       	rcvTcphdr = (struct ps_tcphdr *)(buffer + IPV6HEADER_SIZE);
      	/* int tcpSize = TH_OFF(rcvTcphdr) *4;
       	//cout << "tcpsize " << tcpSize;
       	if ( tcpSize < TCPHEADER_SIZE) {
           cerr << "size of TCP header is less than " << TCPHEADER_SIZE << endl;
           return NO_RESPONSE;
        } 
         //cout << "port is : " << ntohs(rcvTcphdr->th_dport) << endl;

        if ( strcmp(inet_ntop(AF_INET6,oldhdr->ip_src),inet_ntoa(rcvIphdr->ip_dst)) != 0 )  
	{
               return NO_RESPONSE;
        } */

        if (! (ntohs(oldtcphdr->th_sport ) == ntohs(rcvTcphdr->th_dport) && ntohs(oldtcphdr->th_dport ) == ntohs(rcvTcphdr->th_sport))) 
        {
              return NO_RESPONSE;
        }

        //check if ports are similar
        //cout << "flag is = " << ntohs(TH_RST) << " : " << ntohs(rcvTcphdr->th_flags) <<  endl;
        if( scanOptions.compare("SYN") == 0 ) 
	{
              //printf(" SYN TH_RST %d \n",rcvTcphdr->th_flags);
            if (TCPOPTIONS(rcvTcphdr,TH_SYN) == TH_SYN && TCPOPTIONS(rcvTcphdr,TH_ACK) == TH_ACK)
            { 
                //write to log parse from dictionary
                //cout << "open  SYN";
		p.insert(pair<string,string>("SYN","open"));
		return RESPONSE;
            }
             
            else if (TCPOPTIONS(rcvTcphdr,TH_RST) == TH_RST) 
	    {  
                 //cout << " SYN closed";
		 p.insert(pair<string,string>("SYN","closed"));
		 //addtoMap(ntohs(oldtcphdr->th_dport), p);
                 return RESPONSE;
            }
        } 
	else if ( scanOptions.compare("ACK") == 0 ) 
	{       
            if ( TCPOPTIONS(rcvTcphdr , TH_RST) == TH_RST) 
	    {
            	//cout << "ACK unfiltered"; //unfiltered
               
		p.insert(pair<string,string>("ACK","unfiltered"));
		//addtoMap(ntohs(oldtcphdr->th_dport), p);
                return RESPONSE;  
            }
        } 
	else if ( scanOptions.compare("NULL") == 0   || scanOptions.compare("XMAS") == 0  || scanOptions.compare("FIN") == 0)     
        {                              
            string scantype ;
	    if(scanOptions.compare("NULL") == 0)
		scantype = "NULL";
	    else if(scanOptions.compare("XMAS") == 0)
		scantype = "XMAS";
	    else if(scanOptions.compare("FIN") == 0)
		scantype = "FIN";
 	    if ( TCPOPTIONS(rcvTcphdr , TH_RST) == TH_RST) 
 	    {   
            	//cout << "NULL closed";
		p.insert(pair<string,string>(scantype ,"filtered"));
		//addtoMap(ntohs(oldtcphdr->th_dport), p);
                return RESPONSE;
            }
	} 
	return NO_RESPONSE;
}
 
