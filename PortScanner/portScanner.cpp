/*
	A Basic Port Scanner

*/

#include "portScanner.h"



pthread_mutex_t mutexLog= PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t lockLog= PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t lockPort= PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t lockProto= PTHREAD_MUTEX_INITIALIZER;
int gprotocolNum;
int portIndex;
int protocolThIndex;
map<int,map<string, string> > result;

portScannerOpt myOpt;

int main( int argc , char *argv[]) 
{
   args myarg;
   //parse the CommandLine Args and set to class myOpt
   if ( parseOptions(argc,argv,myOpt) == false ) 
   {
      exit(EXIT_FAILURE);
   }
   pthread_t ps_thread[myOpt.getSpeedUp()+1];
   string destIp;  
   bool loopFlag;
   int protocolrangeLength = myOpt.getProtocolRangeLength();

   while( (destIp = myOpt.getDstIpAddress() ) != "NULL" ) 
   {    
        cout <<"\nDestination  IP: "<< destIp << "\n";  
	int protoIndex ;
        args myprotoarg[myOpt.getSpeedUp()+1];
                
	for(protoIndex = 0; protoIndex < protocolrangeLength ; /*protoIndex++*/)
	{       
                portIndex = 0 ;
		int protocolNum ; 
       		loopFlag = true;
       		int thIndex; 
                 
       		for(thIndex = 0; thIndex < myOpt.getSpeedUp()  || loopFlag ; thIndex++ ) 
		{
                        protocolNum = myOpt.getProtocolRange(protoIndex);
          		//myarg.ip = destIp;
          		//myarg.protocolNum = protocolNum;
          		gprotocolNum =   protocolNum;
                        myprotoarg[thIndex].ip =  destIp;
                        myprotoarg[thIndex].protocolNum =  protocolNum;

			/*if ( protocolNum != NO_PROTO &&  protocolNum == IPPROTO_TCP && protocolNum == IPPROTO_UDP)
          		     cout<<"\nProtocol: "<<protocolNum<<"\n";*/
          		switch ( protocolNum ) 
			{
           		    case IPPROTO_TCP: 
                            	//pthread_create(&ps_thread[thIndex],NULL,tcpScan,&myarg);
				pthread_create(&ps_thread[thIndex],NULL,tcpScan,&myprotoarg[thIndex]);
                            	break;
           		    case IPPROTO_UDP:
                            	//pthread_create(&ps_thread[thIndex],NULL,udpScan,&myarg);
				pthread_create(&ps_thread[thIndex],NULL,udpScan,&myprotoarg[thIndex]);
                            	break;
           		    default:				
                  		//pthread_create(&ps_thread[thIndex],NULL,defaultScan,&myarg);
                                pthread_create(&ps_thread[thIndex],NULL,defaultScan,&myprotoarg[thIndex]);
                                protoIndex++;
                  		break; 
        		}
       			if ( myOpt.getSpeedUp() < MIN_THREAD_INSTANCE+1 )
         		    loopFlag = false;
                        if ( thIndex > MIN_THREAD_INSTANCE )
                            loopFlag = false;
      		}
		//cout<<"Thread index: "<<thIndex << "Total threads: "<<myOpt.getSpeedUp()<<"\n";
      		loopFlag = true;
      		for(  int thIndexx = 0; thIndexx < myOpt.getSpeedUp() || loopFlag ; thIndexx++ ) 
		{      
         		pthread_join(ps_thread[thIndexx],NULL);
         		if ( myOpt.getSpeedUp() < MIN_THREAD_INSTANCE+1 )
           		    loopFlag = false;
                        if ( thIndex > MIN_THREAD_INSTANCE )
                            loopFlag = false;
     		}
               if ( protocolNum == IPPROTO_TCP || protocolNum == IPPROTO_UDP)
		  protoIndex++;
  	}
      //free(*myprotoarg);
   }  

}

void *tcpScan(void *arg) 
{
   //printf("The ID of this thread is: %u \n", (unsigned int)pthread_self());
   args *myarg = (args *)arg;
   int protocolNumber;
   protocolNumber= myarg->protocolNum;
   string destIp = myarg->ip;

   bool isIp4;
   int version = ipVersion(destIp);

   if (version == IPV4 ) 
   {
	isIp4 = true;
   }
   else if (version == IPV6 ) 
   { 
        isIp4 = false;
   }  
   else if ( version == NO_IP_FORMAT ) 
   {
       cout << "invalid IP"; 
       pthread_exit(NULL); 
   }

   //extract details from the myOpt class
   int numOfScans =  myOpt.getScanOptionLength() ;
   int sockfd, sockicmpfd;

   //different header class
   buildIpHeader ipPkt;
   buildTcpHeader tcpPkt;
   buildIp6Header ip6Pkt;

   struct ps_tcphdr *tcphdrSend , *tcphdrRecv;
   struct ps_iphdr *iphdrSend , *iphdrRecv;
   struct ps_ip6hdr *ip6hdrSend , *ip6hdrRecv;
   struct sockaddr_in srvaddr;

   struct hostent *hstent, *servTcpIpAddr;
   struct sockaddr_in clientsin;
   struct servent *serv,*poss_serv;
   struct sockaddr_storage recvStorage;    
   struct sockaddr_in6 clientsin6;
   int IPHEADER;

   if ( isIp4)  
       IPHEADER = IPHEADER_SIZE;
   else 
       IPHEADER = IPV6HEADER_SIZE;
   
   int packetLen = PSEUDOHEADER_SIZE+TCPHEADER_SIZE+IPHEADER;

   unsigned char *packetData = new unsigned char[packetLen];
   struct ps_pseudohdr *pseudohdr;
   struct ps_pseudo6hdr *pseudo6hdr;
   unsigned char segment[TCPHEADER_SIZE+PSEUDOHEADER_SIZE+DATA_SIZE];
   unsigned char recvTcpPacketData[packetLen],recvIcmpPacketData[packetLen];
   int portNumber;
  
   pthread_mutex_lock(&lockPort);
    	portNumber=  myOpt.getPort(portIndex);
        portIndex++;
   pthread_mutex_unlock(&lockPort);
     
   //printf("The ID of this thread is: %u and Portnumber is: %d\n", (unsigned int)pthread_self(),portNumber);
  
   while ( portNumber) 
   {  
    if ( protocolNumber != NO_PROTO) 
           cout<<"\nProtocol: "<<protocolNumber<<"\n";
	
        map<string, string> p;
	
   	for ( int index = 0; index < numOfScans; index++ ) 
	{
            setZeroMemory(packetData,packetLen);
            setZeroMemory(segment,TCPHEADER_SIZE+PSEUDOHEADER_SIZE);
            
            //Declare socket TCP
            if ( isIp4) 
              	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
            else
              	sockfd = socket(AF_INET6, SOCK_STREAM, 0);
             
            if(sockfd < 0 ) 
	    {
		delete[] packetData;
                perror("sockfd create : ");
                pthread_exit(NULL);   
            }
            sockicmpfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

            if (sockicmpfd < 0 ) 
	    { 
                perror("socket ICMP connect Error()\n");
                delete[] packetData;
                pthread_exit(NULL);
            }

            //set TCP header
            tcpPkt.setTcpHeader(myOpt.getScanOptions(index),portNumber);
            tcphdrSend = tcpPkt.getTcpHeader();
            
            //set IP header
            if ( isIp4) 
	    { 
            	ipPkt.setIpHeader(myOpt.getSourceIp(),destIp,IPPROTO_TCP);
            	iphdrSend = ipPkt.getIpHeader();
            	createPseudoHeader(&pseudohdr ,iphdrSend);
            	memcpy(segment,(void *)pseudohdr,PSEUDOHEADER_SIZE);
            	memcpy(segment+PSEUDOHEADER_SIZE,(void *)tcphdrSend,TCPHEADER_SIZE);
            	tcphdrSend->th_sum = (CheckSum(segment,TCPHEADER_SIZE+PSEUDOHEADER_SIZE));
            }
            else 
	    {
           	ip6Pkt.setIp6Header(myOpt.getSourceIp(),destIp,IPPROTO_TCP);
            	ip6hdrSend = ip6Pkt.getIp6Header();
            	createPseudoHeader6(&pseudo6hdr ,ip6hdrSend);
            	memcpy(segment,(void *)pseudo6hdr,PSEUDO6HEADER_SIZE);
            	memcpy(segment+PSEUDO6HEADER_SIZE,(void *)tcphdrSend,TCPHEADER_SIZE);
            	tcphdrSend->th_sum = (CheckSum(segment,TCPHEADER_SIZE+PSEUDO6HEADER_SIZE));
            }
            
            if ( isIp4) 
              	memcpy(packetData,(void *)iphdrSend, IPHEADER);
            else
              	memcpy(packetData,(void *)ip6hdrSend, IPHEADER);
            
            memcpy(packetData+IPHEADER,(void *)tcphdrSend,TCPHEADER_SIZE);
            
            if ( isIp4) 
            	free(pseudohdr);
            else
             	free(pseudo6hdr);
            

            //Time to follow socket API and connect
            //see richard stevens chapter-28
            if ( isIp4) 
	    { 
            	clientsin.sin_family = AF_INET;
            	servTcpIpAddr = gethostbyname(destIp.c_str());
            	bcopy((char *)servTcpIpAddr->h_addr, (char *)&clientsin.sin_addr.s_addr, servTcpIpAddr->h_length);
             	clientsin.sin_port=htons(portNumber);
            } 
	    else 
  	    {
            	clientsin6.sin6_family = AF_INET6;
                clientsin6.sin6_flowinfo = 0;
               
            	servTcpIpAddr = gethostbyname2(destIp.c_str(),AF_INET6);
            	bind(sockfd,(struct sockaddr *) &clientsin6 , sizeof(clientsin6));
            	inet_pton(AF_INET6,destIp.c_str(), &(clientsin6.sin6_addr)); 
            	clientsin6.sin6_port=htons(portNumber);
            }

            const int on = 1;
            int setsockStatus;

            if ( isIp4)  {
              	setsockStatus = setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on));
                      
            	if (setsockStatus < 0 ) 
	    	{
            	    cerr<< "Cannot set HDRINCL port";
            	    delete[] packetData;
            	    pthread_exit(NULL);
            	}
            }
            int retransStatus= NO_RESPONSE , icmpStatus = NO_ICMP;
         	
            for(int countRe =0;countRe< NUMBER_RETRANSMISSIONS && (retransStatus == NO_RESPONSE) && ( icmpStatus == NO_ICMP);countRe++)
  	    {       
            	fcntl(sockicmpfd, F_SETFL, O_NONBLOCK);
            	int sendStatus;
            	if ( isIp4)  
              	    sendStatus = sendto(sockfd, packetData, iphdrSend->ip_len, 0, (struct sockaddr *)&clientsin, sizeof(clientsin));
            	else 
		{
             	    sendStatus = sendto(sockfd, packetData, ip6hdrSend->ip6_len, 0, (struct sockaddr *)&clientsin6, sizeof(clientsin6));
            	}
           	if (sendStatus == -1 && errno != EINTR ) 
		{
	            //perror(" error in sendto: ");
		    delete[] packetData; 
                    pthread_exit(NULL);
           	}
           	setZeroMemory(recvTcpPacketData,0);
           	setZeroMemory(recvIcmpPacketData,0);
           	socklen_t fromlen = sizeof (recvStorage);
           
           	fd_set fds;
           	struct timeval tv;
           	FD_ZERO(&fds);
           	FD_SET(sockfd, &fds);
           	FD_SET(sockicmpfd,&fds);
           	tv.tv_sec = TIMEOUT;
           	tv.tv_usec = 0;
           	int selectStatus = select(sockfd+1, &fds, NULL, NULL, &tv);
           	int icmpSelectStatus = select(sockicmpfd+1, &fds, NULL, NULL, &tv);
           	int numbytesTcpRecvd = recvfrom(sockfd, recvTcpPacketData, packetLen , 0,(struct sockaddr *)&recvStorage, &fromlen);
                int numbytesIcmpRecvd = recvfrom(sockicmpfd,recvIcmpPacketData, packetLen , 0,(struct sockaddr *)&recvStorage, &fromlen);
		//bool premoved = false;
           	
           	if ( numbytesTcpRecvd > 0 ) 
		{
                    if ( isIp4) 
		    {
                 	retransStatus = parseTcpHeader(recvTcpPacketData,numbytesTcpRecvd,myOpt.getScanOptions(index),iphdrSend,tcphdrSend, p);
			//premoved = true;
		    }
                    else 
		    {
                    	retransStatus = parseTcpHeader6(recvTcpPacketData,numbytesTcpRecvd,myOpt.getScanOptions(index),ip6hdrSend,tcphdrSend,p);
                    }
                } 
            	else if ( numbytesIcmpRecvd > 0 ) 
		{                
			//cout << "icmp\n"; 
                    if ( isIp4) 
		    {
                   	icmpStatus = parseIcmpHeader(recvIcmpPacketData,numbytesIcmpRecvd,(void *)iphdrSend,ipVersion(destIp));
                    }
		    else 
   		    {
                   	icmpStatus = parseIcmpHeader(recvIcmpPacketData,numbytesIcmpRecvd,(void *)ip6hdrSend,ipVersion(destIp));
                    }
             	}
            } 
		
	    string scans =  myOpt.getScanOptions(index);
            if ( scans.compare("ACK") == 0)  
	    {
            	if (  retransStatus == NO_RESPONSE   || icmpStatus == ICMP_PROTO_UNREACHABLE || icmpStatus == ICMP_UNREACHABLE  || icmpStatus == ICMP_CLOSE)
		{ 
                	//cout << "filtered";
			p.insert(pair<string,string>(scans.c_str(),"filtered"));
		}
            }
	    else if ( scans.compare("XMAS") == 0 || scans.compare("NULL") == 0 || scans.compare("FIN") == 0) 
	    {
                if ( retransStatus == NO_RESPONSE  && icmpStatus == NO_ICMP )
		{
                        //cout << "open|filtered";
			p.insert(pair<string,string>(scans.c_str(),"open|filtered"));
		}
                if ( icmpStatus == ICMP_UNREACHABLE || icmpStatus == ICMP_PROTO_UNREACHABLE || icmpStatus == ICMP_CLOSE)
		{
                      //cout << "filtered";
			p.insert(pair<string,string>(scans.c_str(),"filtered"));
		}
           } 
	   else if ( scans.compare("SYN") == 0)  
	   {
             // WHERE
                //cout << "retransStatus " << retransStatus;
             	if ( retransStatus == NO_RESPONSE ||  icmpStatus == ICMP_UNREACHABLE || icmpStatus == ICMP_PROTO_UNREACHABLE || icmpStatus == ICMP_CLOSE) 
		{
                       //cout << "filtered\n";
			p.insert(pair<string,string>(scans.c_str(),"filtered"));
		}
           }
           close(sockfd);
           close(sockicmpfd); 	           
       	}
	
	pthread_mutex_lock(&lockLog);
	int previousPort;
	previousPort = portNumber;
	result.insert(pair<int,map<string,string> >(previousPort,p));
	map<int,map<string,string> >::iterator outerIter;
	map<string,string>::iterator innerIter;
	outerIter = result.find(previousPort);
	bool portStatus = false;
	cout<<"\nPort:"<<portNumber<<"\n";
	for(innerIter = outerIter->second.begin(); innerIter!= outerIter->second.end(); innerIter++)
	{
		cout<<innerIter->first<<"--->"<<innerIter->second<<"\n";
		if(strcmp(innerIter->first.c_str(),"SYN") == 0 && strcmp(innerIter->second.c_str(),"open") == 0)
			portStatus = true;
	}
	if(portStatus)
		cout<<"Port "<<previousPort<<" Status: open"<<endl;
	result.erase(previousPort);	
	pthread_mutex_unlock(&lockLog);
	
    	pthread_mutex_lock(&lockPort);
    		portNumber=  myOpt.getPort(portIndex);
	        portIndex++;
    	pthread_mutex_unlock(&lockPort);
    	close(sockfd);
    	close(sockicmpfd);
   }
   delete[] packetData; 
}


void *udpScan(void *arg) 
{
   args *myarg = (args *)arg;
   int protocolNumber;
   protocolNumber= myarg->protocolNum;
   string destIp = myarg->ip;
   bool isIp4;
   int version = ipVersion(destIp);

   if (version == IPV4 ) 
   {               
           isIp4 = true;
   }
   else if (version == IPV6 ) 
   {    
           isIp4 = false;
   }  
   else if ( version == NO_IP_FORMAT ) 
   {
       cout << "invalid IP"; 
       pthread_exit(NULL); 
   }

   //extract details from the myOpt class
   int numOfScans =  myOpt.getScanOptionLength();
   int sockfd, sockicmpfd;
   //different header class
   buildIpHeader ipPkt;
   buildUdpHeader udpPkt;
   buildIp6Header ip6Pkt;
   struct ps_udphdr *udphdrSend , *udphdrRecv;
   struct ps_iphdr *iphdrSend , *iphdrRecv;
   struct ps_ip6hdr *ip6hdrSend , *ip6hdrRecv;
   struct sockaddr_in srvaddr;
   
   struct hostent *hstent, *servTcpIpAddr;
   struct sockaddr_in clientsin;
   struct servent *serv,*poss_serv;
   struct sockaddr_storage recvStorage;
   struct sockaddr_in6 clientsin6; 
   int IPHEADER ;

   if ( isIp4) 
       IPHEADER = IPHEADER_SIZE;
   else
       IPHEADER = IPV6HEADER_SIZE;
   
   int packetLen = PSEUDOHEADER_SIZE+UDPHEADER_SIZE+IPHEADER;

   unsigned char *packetData = new unsigned char[packetLen];
   struct ps_pseudohdr *pseudohdr;
   struct ps_pseudo6hdr *pseudo6hdr;
   unsigned char segment[UDPHEADER_SIZE+PSEUDOHEADER_SIZE+DATA_SIZE];
   unsigned char recvUdpPacketData[packetLen],recvIcmpPacketData[packetLen];
   int portNumber;

   pthread_mutex_lock(&lockPort);
    	portNumber=  myOpt.getPort(portIndex);
	portIndex++;
   pthread_mutex_unlock(&lockPort);

   if ( portNumber == 0 ) 
   {
     	delete[] packetData;
      	pthread_exit(NULL);
   }  
 
   while( portNumber) 
   {
	if ( protocolNumber != NO_PROTO) 
           cout<<"\nProtocol: "<<protocolNumber<<"\n";
   	setZeroMemory(packetData,packetLen);
        setZeroMemory(segment,TCPHEADER_SIZE+PSEUDOHEADER_SIZE);
        map<string,string> p;

        //Declare socket TCP
        if ( isIp4)
            sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        else
            sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
             
        if(sockfd < 0 ) 
	{
	     delete[] packetData;
             perror("sockfd create : ");
             pthread_exit(NULL);   
        }

        sockicmpfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
            
        if (sockicmpfd < 0 ) 
	{ 
             perror("socket ICMP connect Error()\n");
             delete[] packetData;
             pthread_exit(NULL);
        }  
        //set UDP header
        udpPkt.setUdpHeader(portNumber);
        udphdrSend = udpPkt.getUdpHeader();
                      
        if ( isIp4 ) 
	{ 
             ipPkt.setIpHeader(myOpt.getSourceIp(),destIp,IPPROTO_UDP);
             iphdrSend = ipPkt.getIpHeader();
             //cout << "IP while sending pkt : = " << inet_ntoa(iphdrSend->ip_src) << " : \n";
             createPseudoHeader(&pseudohdr ,iphdrSend);
             memcpy(segment,(void *)pseudohdr,PSEUDOHEADER_SIZE);
             memcpy(segment+PSEUDOHEADER_SIZE,(void *)udphdrSend,UDPHEADER_SIZE);
             udphdrSend->uh_sum = (CheckSum(segment,UDPHEADER_SIZE+PSEUDOHEADER_SIZE));
             //copy packet
             memcpy(packetData,(void *)iphdrSend, IPHEADER);
             memcpy(packetData+IPHEADER_SIZE,(void *)udphdrSend,UDPHEADER_SIZE);
             free(pseudohdr);           
        }
        else 
	{
             ip6Pkt.setIp6Header(myOpt.getSourceIp(),destIp,IPPROTO_TCP);
             ip6hdrSend = ip6Pkt.getIp6Header();
             createPseudoHeader6(&pseudo6hdr ,ip6hdrSend);
             memcpy(segment,(void *)pseudo6hdr,PSEUDO6HEADER_SIZE);
             memcpy(segment+PSEUDO6HEADER_SIZE,(void *)udphdrSend,UDPHEADER_SIZE);
             udphdrSend->uh_sum = (CheckSum(segment,UDPHEADER_SIZE+PSEUDO6HEADER_SIZE));

	     memcpy(packetData,(void *)ip6hdrSend, IPHEADER);	
             memcpy(packetData+IPHEADER_SIZE,(void *)udphdrSend,UDPHEADER_SIZE);
             free(pseudo6hdr);
	} 
                      
        if ( isIp4) 
	{
            clientsin.sin_family = AF_INET;
            servTcpIpAddr = gethostbyname(destIp.c_str());
            bcopy((char *)servTcpIpAddr->h_addr, (char *)&clientsin.sin_addr.s_addr, servTcpIpAddr->h_length);
            clientsin.sin_port=htons(portNumber);
        }
        else 
	{
            clientsin6.sin6_family = AF_INET6;
            clientsin6.sin6_flowinfo = 0;
            servTcpIpAddr = gethostbyname2(destIp.c_str(),AF_INET6);
            bind(sockfd, ( struct sockaddr *) &clientsin6,sizeof(clientsin6));
            clientsin6.sin6_port=htons(portNumber);
        } 

        int retransStatus= NO_RESPONSE,icmpStatus  = NO_ICMP;
        for(int countRe =0;countRe< NUMBER_RETRANSMISSIONS && (retransStatus == NO_RESPONSE) && ( icmpStatus == NO_ICMP);countRe++)
	{
            const int on = 1;
            int setsockStatus;
            if ( isIp4) {
            	setsockStatus = setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on));
           
            	if (setsockStatus < 0 ) 
	    	{
            	    cerr<< "Cannot set HDRINCL port";
            	    delete[] packetData;
            	    pthread_exit(NULL);
            	}
	    }
            fcntl(sockicmpfd, F_SETFL, O_NONBLOCK);
            fcntl(sockfd, F_SETFL, O_NONBLOCK);
            int sendStatus;
           
            if ( isIp4)
            	sendStatus = sendto(sockfd, packetData, iphdrSend->ip_len, 0, (struct sockaddr *)&clientsin, sizeof(clientsin)) ;
            else 
	    {
            	sendStatus = sendto(sockfd, packetData, ip6hdrSend->ip6_len, 0, (struct sockaddr *)&clientsin6, sizeof(clientsin6)) ;
		
            }
           
            if (sendStatus == -1 && errno != EINTR ) 
	    {
            	//perror(" error in sendto: ");
                delete[] packetData; 
            	pthread_exit(NULL);
            }
            setZeroMemory(recvUdpPacketData,0);
            setZeroMemory(recvIcmpPacketData,0);
            socklen_t fromlen = sizeof (recvStorage);
           
            fd_set fds;
            struct timeval tv;
            FD_ZERO(&fds);
            FD_SET(sockfd, &fds);
            FD_SET(sockicmpfd,&fds);
            tv.tv_sec = TIMEOUT+1;
            tv.tv_usec = 0;
            int selectStatus = select(sockfd+1, &fds, NULL, NULL, &tv);
            int icmpSelectStatus = select(sockicmpfd+1, &fds, NULL, NULL, &tv);        
            int numbytesIcmpRecvd = recvfrom(sockicmpfd,recvIcmpPacketData, packetLen , 0,(struct sockaddr *)&recvStorage, &fromlen);
           
            if ( numbytesIcmpRecvd > 0 ) 
	    {
            	icmpStatus =  parseIcmpHeader(recvIcmpPacketData,numbytesIcmpRecvd,(void *)iphdrSend,version);
            } 
            int numbytesUdpRecvd = recvfrom(sockfd, recvUdpPacketData, packetLen , 0,(struct sockaddr *)&recvStorage, &fromlen);  
            //WHERE
	    //http://linux.die.net/man/2/recvfrom
            if ( numbytesUdpRecvd > 0 ) 
	    {
            	retransStatus = parseUdpHeader(recvUdpPacketData,numbytesUdpRecvd,(void *)iphdrSend,udphdrSend,version);
            }    
   	} //retransmission loop ends , lets check

   	//According to nmap guide:
   	if ( icmpStatus == NO_ICMP) 
   	{
	    p.insert(pair<string,string>("UDP","open|filtered"));
	    int previousPort;
	    previousPort = portNumber;
	    result.insert(pair<int,map<string,string> >(previousPort,p));
	    map<int,map<string,string> >::iterator outerIter;
	    map<string,string>::iterator innerIter;
	    outerIter = result.find(previousPort);
	    cout<<"\nPort:"<<previousPort<<"\n";

	    for(innerIter = outerIter->second.begin(); innerIter!= outerIter->second.end(); innerIter++)
	    {
		cout<<innerIter->first<<"--->"<<innerIter->second<<"\n";	
	    }
	    result.erase(previousPort);
        } 
        else 
        {  
            if ( icmpStatus == ICMP_CLOSE )
	    {
            	//cout << "Closed\n";
	    	p.insert(pair<string,string>("UDP","Closed"));		
	    }
    	    else if (  icmpStatus == ICMP_UNREACHABLE || icmpStatus == ICMP_PROTO_UNREACHABLE)
	    {
            	//cout << "open|filtered\n";
	    	p.insert(pair<string,string>("UDP","open|filtered"));
	    }
      	    else if ( retransStatus == RESPONSE ) // for this case it will not come as we send no payload
	    {
            	//cout << "Udp port is open\n";
	    	p.insert(pair<string,string>("UDP","open"));
	    }
	    int previousPort;
	    previousPort = portNumber;
	    result.insert(pair<int,map<string,string> >(previousPort,p));
	    map<int,map<string,string> >::iterator outerIter;
	    map<string,string>::iterator innerIter;
	    outerIter = result.find(previousPort);
	    cout<<"\nPort:"<<previousPort<<"\n";

	    for(innerIter = outerIter->second.begin(); innerIter!= outerIter->second.end(); innerIter++)
	    {
		cout<<innerIter->first<<"--->"<<innerIter->second<<"\n";	
	    }
	    result.erase(previousPort);
        }
        close(sockfd);
        close(sockicmpfd);           
        pthread_mutex_lock(&lockPort);
        result.insert(pair<int,map<string,string> >(portNumber,p));
        portNumber=  myOpt.getPort(portIndex);
        portIndex++;
        pthread_mutex_unlock(&lockPort);  
   }
   delete[] packetData;
}


void *defaultScan(void *arg) 
{
   int protocolNumber;
   pthread_mutex_lock(&lockProto);   
    args *myarg = (args *)arg;
    // memcpy(myarg,arg,sizeof(args));
    string destIp = myarg->ip;
    protocolNumber= myarg->protocolNum;
   pthread_mutex_unlock(&lockProto);

	
   //cout << "prno " << protocolNumber;
   bool isIp4;
   if ( protocolNumber == NO_PROTO ) 
      pthread_exit(NULL);
   int version = ipVersion(destIp);
   
   if (version == IPV4 ) 
   {
   	isIp4 = true;
   }
   else if (version == IPV6 ) 
   {
   	isIp4 = false;
   }  
   else if ( version == NO_IP_FORMAT ) 
   {
       cout << "invalid IP " << destIp; 
       pthread_exit(NULL); 
   }   
    //WHERE
   struct ps_iphdr *iphdrSend , *iphdrRecv;
   struct ps_ip6hdr *ip6hdrSend , *ip6hdrRecv;
   struct sockaddr_in srvaddr;
   //need to change variable name
   struct hostent *hstent, *servTcpIpAddr;
   struct sockaddr_in clientsin;
   struct servent *serv,*poss_serv;
   struct sockaddr_storage recvStorage;
   struct sockaddr_in6 clientsin6;
   int sockfd;
   int IPHEADER ;

   if ( isIp4) 
       IPHEADER = IPHEADER_SIZE;
   else
       IPHEADER = IPV6HEADER_SIZE;

   int packetLen = IPHEADER + ICMPHEADER_SIZE;
   unsigned char *packetData = new unsigned char[packetLen];
   unsigned char recvIcmpPacketData[packetLen];
   buildIpHeader ipPkt;
   buildIp6Header ip6Pkt;  
   int portNumber = 8971;  
	map<string,string> p;
  // pthread_mutex_lock(&lockProto);
  // portNumber=  myOpt.getPort(portIndex);
	//portIndex++;
  // pthread_mutex_unlock(&lockProto);
   int icmpStatus;
   
 ///  while ( portNumber) 
  // {  
     //printf("The ID of this thread is: %u and Protocol is: %d\n", (unsigned int)pthread_self(),protocolNumber);
   	setZeroMemory(packetData,packetLen);
     	
     	if ( isIp4)
            sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
      	else
            sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);

     	if(sockfd < 0 ) 
	{
            delete[] packetData;
            perror("sockfd create : ");
            pthread_exit(NULL);   
        }
        int sockicmpfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if ( isIp4 ) 
	{   
	    ipPkt.setIpHeader(myOpt.getSourceIp(),destIp,protocolNumber);
            iphdrSend = ipPkt.getIpHeader();
            memcpy(packetData,(void *)iphdrSend, IPHEADER);
            struct ps_iphdr *tmphdr  = (struct ps_iphdr *)packetData;
            tmphdr->ip_sum = CheckSum(packetData,IPHEADER_SIZE);
            if ( protocolNumber == IPPROTO_ICMP ) 
	    {            
       		struct icmp *icmphdr = ( struct icmp *)(packetData+IPHEADER);
       		icmphdr->icmp_type = ICMP_ECHO;
       		icmphdr->icmp_code = 0;
	       	icmphdr->icmp_seq = htons(0);
       		icmphdr->icmp_id = htons(100);
       		icmphdr->icmp_cksum = (CheckSum(packetData,ICMPHEADER_SIZE+IPHEADER_SIZE));
       	    }
      	}
      	//add Here for IPV6
     	if ( isIp4) 
	{            
      	     clientsin.sin_family = AF_INET;
             servTcpIpAddr = gethostbyname(destIp.c_str());
             bcopy((char *)servTcpIpAddr->h_addr, (char *)&clientsin.sin_addr.s_addr, servTcpIpAddr->h_length);
             clientsin.sin_port=htons(portNumber);
    	}     
   	//add here for IPV6
    	icmpStatus  = NO_ICMP;

    	for(int countRe =0;countRe< NUMBER_RETRANSMISSIONS &&  ( icmpStatus == NO_ICMP);countRe++)
	{
     	    const int on = 1;
     	    int setsockStatus;
            if ( isIp4) 
	    {
      		setsockStatus = setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on));
                if (setsockStatus < 0 ) 
		{
		     cerr<< "Cannot set HDRINCL port";
         	     delete[] packetData;
         	     pthread_exit(NULL);
      		}
     	    }
     	    int sendStatus;
		
     	    if ( isIp4)
       	    	sendStatus = sendto(sockfd, packetData, iphdrSend->ip_len, 0, (struct sockaddr *)&clientsin, sizeof(clientsin)) ;
     	    else 
	    {
	    	//sendStatus = sendto(sockfd, packetData, ip6hdrSend->ip_len, 0, (struct sockaddr *)&clientsin6, sizeof(clientsin6)) ;
            }
        
     	    if (sendStatus == -1 && errno != EINTR ) 
	    {
            	//perror(" error in sendto: ");
                delete[] packetData; 
            	pthread_exit(NULL);
     	    }
     		
            //analysePacket 
     	    fcntl(sockicmpfd, F_SETFL, O_NONBLOCK);
     	    fd_set fds;
     	    struct timeval tv;
     	    FD_ZERO(&fds);
     	    FD_SET(sockfd, &fds);
     	    FD_SET(sockicmpfd,&fds);
     	    tv.tv_sec = TIMEOUT;
     	    tv.tv_usec = 0;
     	    int selectStatus = select(sockicmpfd+1, &fds, NULL, NULL, &tv); 
     	    setZeroMemory(recvIcmpPacketData,0);
     	    socklen_t fromlen = sizeof (recvStorage);
     	    int numbytesIcmpRecvd = recvfrom(sockicmpfd,recvIcmpPacketData, packetLen , 0,(struct sockaddr *)&recvStorage, &fromlen);
     	    if( numbytesIcmpRecvd > 0 ) 
     	    icmpStatus = parseIcmpHeader(recvIcmpPacketData,numbytesIcmpRecvd,(void *)iphdrSend,version);
		
       	}
	
	string protocolName;
     	struct protoent *servptr;
     	if(!(servptr = getprotobynumber(protocolNumber)))
		protocolName = "N/A";
        else
     	   protocolName = servptr->p_name;
     	
	if ( icmpStatus == ICMP_REPLY )
	{
            //cout << "open";
	    p.insert(pair<string,string>(protocolName,"open"));
	}
     	else if ( icmpStatus == ICMP_PROTO_UNREACHABLE ) 
	{
            //cout << "closed";
	    p.insert(pair<string,string>(protocolName,"closed"));
	}
        else if ( icmpStatus == NO_ICMP ) 
	{
            //cout << "open|filtered";		
	    p.insert(pair<string,string>(protocolName,"open|filtered"));
	}
        else if ( icmpStatus == ICMP_UNREACHABLE || icmpStatus == ICMP_CLOSE )
	{
            //cout << "filtered";
	    p.insert(pair<string,string>(protocolName,"filtered"));
	}
	
	//int previousPort;
	//previousPort = portNumber;
	cout<<"\nProtocol: "<<protocolNumber<<"\n";
	result.insert(pair<int,map<string,string> >(protocolNumber,p));
	map<int,map<string,string> >::iterator outerIter;
	map<string,string>::iterator innerIter;
	outerIter = result.find(protocolNumber);
	//cout<<"\nProtocol: "<<protocolNumber<<"\n";

	for(innerIter = outerIter->second.begin(); innerIter!= outerIter->second.end(); innerIter++)
	{
	    cout<<innerIter->first<<"--->"<<innerIter->second<<"\n";	
	}
	result.erase(protocolNumber);

        //pthread_mutex_lock(&lockPort);
	    //result.insert(pair<int,map<string,string> >(protocolNumber,p));
      	   // portNumber=  myOpt.getPort(portIndex);
	   // portIndex++;
      	//pthread_mutex_unlock(&lockPort);
   // }
    delete[] packetData;
}
