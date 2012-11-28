/*
	

*/

#include <stdlib.h>
#include <vector>
#include <list>
#include<iostream>
#include<string>
#include <map>
#include<stack>
#include<set>
#include<string.h>
#include<stdlib.h>
#include <sys/stat.h>
#include <fstream>
#include<queue>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include<netdb.h>
#include<stdio.h>
#include<netinet/ip_icmp.h>
#include"packets.h"
#include<math.h>
#include<ifaddrs.h>

#define IPV4 4
#define IPV6 6
#define NO_PROTO -1
#define MAX_THREADS 1200
#define SIZE 1024
#define DATA_SIZE 1000
#define BUFFER_SIZE 1024
#define MAX_INT_BYTE 32
#define BASE 10
#define DEBUG
//#ifdef DEBUG
#define WHERE fprintf(stdout,"%s:%d\n", __FILE__, __LINE__);
//#endif
using namespace std;

#define LENGTH_CHAR_ARRAY(X)  ( sizeof(X) / sizeof(char *))
enum PORTSERVICE { SSH = 22 , HTTP = 80 , WHOIS = 43 , POP3 =  110 , IMAP = 143 , SMTP = 25 };
static const char *scanOptionSet[6] = { "SYN", "NULL", "FIN", "XMAS" ,"ACK", "END"};
#define MAX_PORT 1024
#define MIN_PORT 1
#define TOTAL_PORTS 65535
#define UDPHEADER_SIZE	sizeof(struct ps_udphdr)
#define TCPHEADER_SIZE	sizeof(struct ps_tcphdr)
#define IPHEADER_SIZE	sizeof(struct ps_iphdr)
#define IPV6HEADER_SIZE	sizeof(struct ps_ip6hdr)
#define PSEUDOHEADER_SIZE sizeof(struct ps_pseudohdr)
#define PSEUDO6HEADER_SIZE sizeof(struct ps_pseudo6hdr)
#define ICMPHEADER_SIZE sizeof( struct icmp)

#define TOTAL_PROTOCOLS 256
#define HOP_LIMIT 64
#define NODATA -1

class StringTokenizer
{
   private:
   	string  token_str;
   	string  delimiter;

   public:
   	StringTokenizer(const string& str, const string& delimiter) 
	{	
   	    if ((delimiter.length() == 0) || (str.length() == 0)) return;
	    this->token_str = str;
   	    this->delimiter = delimiter;
  	}
  	~StringTokenizer(){};

   	bool  hasMoreTokens() 
	{
     	    return (this->token_str.length() > 0);
        }
        string nextToken()
  	{
   	    if (token_str.length() == 0)
            	return "";

   	    string  tmp_str = "";
   	    size_t pos     = token_str.find(delimiter,0);
   	    int start = 0;
   	    if (pos != string::npos) //npos is the const
   	    {
      		tmp_str   = token_str.substr(start,pos);
      		token_str = token_str.substr(pos+delimiter.length(),token_str.length()-pos);
   	    }
   	    else
   	    {
      		tmp_str   = token_str.substr(start,token_str.length());
      		token_str = "";
   	    }
   	return tmp_str;
    }
 
};

class portScannerOpt 
{
   private:   
     	short ipVersion;
     	//queue<int> ports;
     	vector<int> ports;
     	string transport;
     	string srcIpAddress;
     	string srcIp6Address;
     	stack<string> destIpAddress;
     	string fileName;
     	int speedUp;
     	string prefix;
     	vector<string> scanOption;  
     	vector<int> protocol_range;
   public:
   	portScannerOpt() 
	{      
            for(int i = MIN_PORT; i <= MAX_PORT; i++ ) 
	    {
            	//ports.push(i);                 
		ports.push_back(i);
            }
	    //add 0 to mark the end
	    //int portsLen = ports.size();
	    ports.push_back(0);

	    for(int j = MIN_PORT; j <= TOTAL_PROTOCOLS; j++)
	    {
		protocol_range.push_back(j);
	    }

            //set speedup
            this->speedUp = 0;
            //set filename         
            this->fileName = "";
            // set ipaddress
            destIpAddress.push("127.0.0.1");
            //set scanOptions   
            for(int i= 0; strcmp(scanOptionSet[i],"END") != 0 ; i++ )
           	scanOption.push_back(scanOptionSet[i]);
        	
    	    //set ipType
            this->ipVersion = 0;  
            //set transport protocols
            transport = "TCP";
            transport += "UDP";
            //transport.push("ICMP");       
      	}
     	~portScannerOpt() { }

     	void setPort(const string& portSet) 
	{
       	    //tokenize
       	    if ( portSet.length() == 0 )
          	return;
       	    char *pch , *token;
       	    char *tempStore;
       	    tempStore = new char[portSet.length()+1];
       	    memcpy(tempStore,portSet.c_str(),portSet.length()+1);
       	    int portLists[TOTAL_PORTS] = {0} , count = 0;
       		
	    if ( ( pch = strchr(tempStore,','))  != NULL ) 
	    {
            	try 
		{
                    char *garbage = NULL;
                    StringTokenizer strtokn(portSet,",");
                    while(strtokn.hasMoreTokens() ) 
		    {
	        	string temp = strtokn.nextToken();
                    	StringTokenizer innerStrTokn(temp,"-");
                    	string inntkn = innerStrTokn.nextToken();
                    	int start = strtol(inntkn.c_str(), &garbage, 0);
                    	if ( *garbage != '\0')
  		      	    throw "Invalid Port";
                    	portLists[count++] = start;
                    	if (innerStrTokn.hasMoreTokens()) 
			{
                            inntkn = innerStrTokn.nextToken();
                            int end = strtol(inntkn.c_str(), &garbage, 0);
                            if ( *garbage != '\0' ) 
  		        	throw "Invalid Port";
                       	    if ( start > end || (start < MIN_PORT || end < MIN_PORT ) || ( end > TOTAL_PORTS)) 
                         	throw "Invalid Port";
                       	    portLists[count++] = end;
                        } 
                    	portLists[count++] = -1;
                } 
            }
	    catch ( const char *errMsg) 
	    {
       		cout << "exception raised while parsing port : " <<  errMsg << "\n";
                return;
            }

            while (!ports.empty())
                  ports.pop_back();
            
	    set<int> myset; //check for duplicate entries
            set<int>::iterator it;
             		
            for(int k = 0 ; k < count ; ) 
	    {
                int start = portLists[k];
                if (portLists[k+1] != -1 ) 
		{
                    for(int p = start ; p <= portLists[k+1] ; p++ )
                    	myset.insert(p);

                    k += 3;  
                } 
		else 
		{
                    myset.insert(start);
                    k += 2;
                }
	    }              
            for (it=myset.begin(); it!=myset.end(); it++)
            	ports.push_back(*it);     			
       	}
	else if ( ( pch = strchr(tempStore,'-'))  != NULL ) 
	{
	     try 
	     {
                const char *err = "invalid port Number";
                char *garbage = NULL;
               	StringTokenizer strtokn(portSet,"-"); 
          	string tempIp = strtokn.nextToken();
                int start = strtol(tempIp.c_str(), &garbage, 0);
                //cout << "gbg  " << garbage << endl;
                if ( *garbage != '\0') 
  		    throw err;
                tempIp = strtokn.nextToken();
                //garbage = NULL;
                int end = strtol(tempIp.c_str(), &garbage, 0);
                if ( *garbage != '\0' ) 
  		    throw err; 
                if ( start > end || (start <= 0 || end <= 0 ) ) 
                    throw err;
                while (!ports.empty())
                    ports.pop_back();

       		for(int j = start; j <= end ; j++ )
                   ports.push_back(j); 
              } 
	      catch( const char *str) 
	      {
              	 cout << "Exception raised: " << str << '\n';
	      }
       	} 
	else 
	{
            try 
	    {
            	char *garbage = NULL;
            	int tempPort = strtol(tempStore, &garbage, 0);
            	if ( *garbage != '\0') 
               	     throw "invalid port Number";
            	if ( tempPort <= 0 || tempPort > TOTAL_PORTS )
               	     throw "invalid port Number"; 
      		while ( !ports.empty() )
              		ports.pop_back();
            		ports.push_back(tempPort);
            } 
	    catch(const char *str) 
	    {
           	cout << "Exception raised: " << str << '\n';
            }
       	}

	//cout<<ports[1]<<":"<<ports[2];
	ports.push_back(0);
      	delete[] tempStore;     
   } 

   int getPort(int index) 
   {
      	int tmp = 0;
      	if ( index < this->getPortsSize() ) 
	{
            tmp = ports[index];
      	}
      	return tmp;
   } 

   int getPortsSize()
   {
	return ports.size();
   }

   
	void setProtocolRange(const string& protocolRangeSet)
	{
		
		//tokenize
		if ( protocolRangeSet.length() == 0 )
        	  	return;
       		char *pch , *token;
       		char *tempStore;
       		tempStore = new char[protocolRangeSet.length()+1];
       		memcpy(tempStore,protocolRangeSet.c_str(),protocolRangeSet.length()+1);
       		int protocolLists[TOTAL_PROTOCOLS] = {0} , count = 0;
			
		if ( ( pch = strchr(tempStore,','))  != NULL ) 
		{
        		try 
			{	
                 		char *garbage = NULL;
                 		StringTokenizer strtokn(protocolRangeSet,",");
                 		while(strtokn.hasMoreTokens() ) 
				{
                    			string temp = strtokn.nextToken();
                    			StringTokenizer innerStrTokn(temp,"-");
                    			string inntkn = innerStrTokn.nextToken();
                    			int start = strtol(inntkn.c_str(), &garbage, 0);
                    			if ( *garbage != '\0')
  		      				throw "Invalid protocol Input";
                    			protocolLists[count++] = start;
                    			if (innerStrTokn.hasMoreTokens()) 
					{
                        			inntkn = innerStrTokn.nextToken();
                        			int end = strtol(inntkn.c_str(), &garbage, 0);
                        			if ( *garbage != '\0' ) 
  		        				throw garbage;
                       				if ( start > end || (start < MIN_PORT || end < MIN_PORT ) || ( start > TOTAL_PROTOCOLS  || end > TOTAL_PROTOCOLS )) 
                         				throw "Invalid Protocol-Range\n";
                       				protocolLists[count++] = end;
                       
                    			} 
                    			protocolLists[count++] = -1;
                		} 
               		}
			catch ( const char *errMsg) 
			{
                   		cout << "exception raised while protocol-range : " << errMsg;
                   		return;
            		}
              		while (!protocol_range.empty())
                  		protocol_range.pop_back();
              		set<int> myset; //check for duplicate entries
              		set<int>::iterator it;
             
              		cout << endl;
              		for(int k = 0 ; k < count ; ) 
			{
                    		int start = protocolLists[k];
                    		if (protocolLists[k+1] != -1 ) 
				{
	                       		for(int p = start ; p <= protocolLists[k+1] ; p++ )
                            			myset.insert(p);
                      			k += 3;  
                    		} 
				else 
				{
                       			myset.insert(start);
                       			k += 2;
                   		}
               		}              
              		for (it=myset.begin(); it!=myset.end(); it++)
                  		protocol_range.push_back(*it);
       		}
		else if ( ( pch = strchr(tempStore,'-'))  != NULL ) 
		{
          		try 
			{
                		const char *err = "invalid protocol-range";
                		char *garbage = NULL;
                		StringTokenizer strtokn(protocolRangeSet,"-"); 
          			string tempIp = strtokn.nextToken();
                		int start = strtol(tempIp.c_str(), &garbage, 0);
                		if ( *garbage != '\0')
  		  			throw err;
                		tempIp = strtokn.nextToken();
                		garbage = NULL;
                		int end = strtol(tempIp.c_str(), &garbage, 0);
                		if ( *garbage != '\0' ) 
  		  			throw err; 
                		if ( start > end || (start < MIN_PORT || end < MIN_PORT ) || (start > TOTAL_PROTOCOLS  || end > TOTAL_PROTOCOLS  )) 
                 			throw err;
                		while (!protocol_range.empty())
                  			protocol_range.pop_back();
                		for(int j = start; j <= end ; j++ )
                   			protocol_range.push_back(j); 
              		} 
			catch( const char *str) 
			{
                		cout << "Exception raised: " << str << '\n';
              		}
       		}
		else 
		{
          		try 
			{
            			char *garbage = NULL;
            			int tempProtocol = strtol(tempStore, &garbage, 0);
            			if ( *garbage != '\0') 
               				throw "invalid protocol Number";
            			if ( tempProtocol <= 0 || tempProtocol > TOTAL_PROTOCOLS )
               				throw "invalid protocol range"; 
             			while ( !protocol_range.empty() )
              				protocol_range.pop_back();
            
            			protocol_range.push_back(tempProtocol);
         		} 
			catch(const char *str) 
			{
		           	cout << "Exception raised: " << str << '\n';
         		}
       		}
      		delete[] tempStore;     
	}
	
	int getProtocolRange(int index)
	{
            
             if ( index >= this->getProtocolRangeLength() )
                 return NO_PROTO;
	     return protocol_range[index];
	}

	int getProtocolRangeLength()
	{
		return protocol_range.size();
	}
      
   void setDstIpAddress(const string ipAddr, int version) 
   {
       //check ip is valid or not
        struct hostent *he;
        struct in_addr **addr_list;
        char tempHost[SIZE];
        memcpy(tempHost,ipAddr.c_str(),ipAddr.length()+1);
        if ( version == IPV4 ) 
	{
            he = gethostbyname(tempHost);
            if( he == NULL ) 
   	    {
                //WHERE
          	cout << "The hostname can't be resolved so default is local scan\n";
          	return;
            } 
        
            if( !ipAddr.empty()) 
	    {
         	destIpAddress.pop();
        	addr_list = (struct in_addr **)he->h_addr_list;
        	for(int i = 0; addr_list[i] != NULL ; i++ ) 
		{
          	    string temp = inet_ntoa(*addr_list[i]); 
          	    //cout << temp.c_str();
          	    destIpAddress.push(temp);
        	}  
       	    } 
      	} 
	else 
	{
            destIpAddress.pop();
            destIpAddress.push(tempHost);
        }
   } 

   void setSpeedUp(int speedUp ) 
   {  
   	if( speedUp > 0  && speedUp < MAX_THREADS) 
   	   this->speedUp = speedUp; 
   } 

   void setFile(const string& file )    
   {
      	//check if string not NULL
      	struct stat fileStat; 
      	if ( file.length())  
	{   
            this->fileName =  file;
            if(stat(this->fileName.c_str(),&fileStat) < 0)  
	    {
            	cout << "file : " << file.c_str() << " not present \n";
            	return;
            }
         
            ifstream sample(this->fileName.c_str());
            string lines;
            if ( sample.is_open() ) 
	    {
              	while(!sample.eof()) 
	    	{
		    getline(sample,lines); 
			//cout<<"Lines: "<<lines<<endl; 
                    this->destIpAddress.push(lines);
            	}
                sample.close();
            }
       	} 
   } 


   void setScanOptions(const string& options) 
   {
      	char *tempStr;
      	tempStr = new char[strlen(options.c_str())+1];
      	strncpy(tempStr,options.c_str(),strlen(options.c_str())+1);
      	scanOption.clear();
      	char *token = strtok(tempStr," \t");
      	while(token != NULL ) 
	{
      	    bool found = false;
       	    for(int i= 0; strcmp(scanOptionSet[i],"END") != 0 && !found ; i++ )  
	    {
            	if(strcmp(token,scanOptionSet[i]) == 0)
               	    found = true;
            }
            if ( found )
           	scanOption.push_back(token);
        	token=strtok(NULL," \t"); 
       	}
      
       	if (scanOption.empty()) 
	{
           for(int i= 0; strcmp(scanOptionSet[i],"END") != 0 ; i++ )
           	scanOption.push_back(scanOptionSet[i]);
        }
        delete[] tempStr;
   }

   int getScanOptionLength() 
   { 
   	return scanOption.size();
   }

   int getStartPort() 
   {
        return ports.front(); 
   }
   
   int getLastPort() 
   {
   	return ports.back(); 
   }

   int getSpeedUp() 
   { 
       	return this->speedUp; 
   }

   string getScanOptions(int index) 
   {
   	if ( !scanOption.empty() && index < scanOption.size())
   	    return scanOption.at(index);
        return "NO_SCAN";
   } 

   string  getDstIpAddress() 
   {
      	string tempIp = "NULL";
      	if ( !destIpAddress.empty() ) 
	{ 
       	    tempIp = destIpAddress.top();
       	    destIpAddress.pop();
       	    //destIpAddress.push(tempIp); 
      	}
       return tempIp;
   } 

   void setSourceIp() 
   {
    
    //http://www.kernel.org/doc/man-pages/online/pages/man3/getifaddrs.3.html

      	struct ifaddrs *interfaces=NULL , *ifIter;
      	getifaddrs(&interfaces);
      	void *tmpIf;
      	char IPV4address[INET_ADDRSTRLEN] , IPV6address[INET6_ADDRSTRLEN];
      	string srcIpAddress, srcIp6Address;
      	ifIter = interfaces;
      	bool tracklov4 = false , tracklov6 = false;
      	while ( ifIter != NULL ) 
	{
            switch(ifIter->ifa_addr->sa_family) 
	    {
          	case AF_INET:
             	    	tmpIf = &((struct sockaddr_in *)ifIter->ifa_addr)->sin_addr;
             		inet_ntop(AF_INET,tmpIf,IPV4address, INET_ADDRSTRLEN);       
             		//if ( strncmp(IPV4address,"127.0.0.1",9 ) != 0 )
              		 //tracklov4 = true;
             		this->srcIpAddress = IPV4address;
             		break;
          	case AF_INET6:
             		tmpIf = &((struct sockaddr_in6 *)ifIter->ifa_addr)->sin6_addr;
             		inet_ntop(AF_INET6,tmpIf,IPV6address, INET6_ADDRSTRLEN);
             		//if ( strncmp(IPV6address,"::1",3 ) != 0 )
              		//tracklov6 = true;
             		this->srcIp6Address = IPV6address;
             		break;
       	    }
     	    ifIter = ifIter->ifa_next;          
   	} 
   	freeifaddrs(interfaces);
   	//cout << "Ips " << srcIpAddress << "v6 " << srcIp6Address;
  	//this->srcIpAddress = "127.0.0.1";
    } 


    string getSourceIp() 
    {
      	return this->srcIpAddress;
    }


    string getSourceIp6() 
    {
      	return this->srcIp6Address;
    }


    void setIpVersion(int x ) 
    {
      	memcpy(&(this->ipVersion),&x,sizeof(short));
    }


    int getIpVersion() 
    {
      	return this->ipVersion;
    }

   //http://www.ipligence.com/faq
    void setIpPrefix(string ipAddr, int masknet, int version) 
    {
   	if ( version == IPV4 ) 
	{
    	    string tempIp = ipAddr , nxtToken; 
    	    StringTokenizer strtokn(tempIp,".");
	    int hostnets = 4,count = 0;
	    int num[hostnets];
	    //if its 10.2.3.0 num[0] = 10 num[1] = 2
	    while(strtokn.hasMoreTokens() ) 
	    {
       		nxtToken = strtokn.nextToken();
       		num[count++] = atoi(nxtToken.c_str());
     	    }
	     long htonlIpValue = ( num[0] * ( 256 * 256 * 256)) + ( num[1] * ( 256 * 256)) + ( num[2] * 256 ) + num[3];
	     long totalIter = pow(2,(32 - masknet));
	     struct sockaddr_in storeAddr;
	     char *cp;
	     string dstNewIp ;
	     for(long count = 0 ; count < totalIter ; count ++ ) 
	     {
	        storeAddr.sin_addr.s_addr = htonlIpValue+count;
	        cp = inet_ntoa(storeAddr.sin_addr); // it generates Ips in format = 35.4.2.10
	        //cout << cp << endl;
	        tempIp = cp;
	        StringTokenizer nstrtokn(tempIp,".");
	        int innercount = 0;
	        while(nstrtokn.hasMoreTokens()) 
		{
	      	    if ( dstNewIp.length() == 0 )
	            	dstNewIp = nstrtokn.nextToken();
	      	    else 
	        	dstNewIp = nstrtokn.nextToken() + string(".") + dstNewIp; 
      		    
		    if ( innercount == 3 ) 
		    {
		        //cout << dstNewIp << endl;
        		destIpAddress.push(dstNewIp);
        		dstNewIp = "";
       		    }
	            innercount++;
       
      		}
    	    }  
   	} 
	if ( version == IPV6 ) 
	{
	    struct sockaddr_in6 sa;
 	    char str[INET6_ADDRSTRLEN],strOld[INET6_ADDRSTRLEN],*strIp;
 	    //cout << INET6_ADDRSTRLEN;
	    // store this IP address in sa:

	    inet_pton(AF_INET6, ipAddr.c_str(), &(sa.sin6_addr));
 	    //for(int i = 0; i < 16; i++ )
   		//printf(" %d ",sa.sin6_addr.s6_addr[i]);
	    int counts[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},end = 15;
 	    for(int i = 0 ; i < 16; i++)
   		strOld[i] =  sa.sin6_addr.s6_addr[i];
 	    bool flag[15] = {false};

 	    for ( long count = 0 ; count < pow(2,(128-masknet)) ; count ++ ) 
	    {
   		if ( sa.sin6_addr.s6_addr[end] + 1 > 255 ) 
		{
     		    flag[end] = false;
     		    end -= 1;
     		    flag[end] = true;
     		    for(int i = 0 ; i < 16; i++)
       			sa.sin6_addr.s6_addr[i] = strOld[i];
              	}
   		if ( flag[14]) 
		{
     		    sa.sin6_addr.s6_addr[15] += 1;
     		    sa.sin6_addr.s6_addr[14] += 1;
  	 	} 
		else if (flag[13]) 
		{
      		    sa.sin6_addr.s6_addr[15] += 1;
      		    sa.sin6_addr.s6_addr[14] += 1;
     		    sa.sin6_addr.s6_addr[13] += 1;
  	 	}  
		else if ( flag[12]) 
		{
      		    sa.sin6_addr.s6_addr[15] += 1;
      		    sa.sin6_addr.s6_addr[14] += 1;
      		    sa.sin6_addr.s6_addr[13] += 1;
      		   sa.sin6_addr.s6_addr[12] += 1;
    		} 
		else if ( flag[11]) 
		{
      		    sa.sin6_addr.s6_addr[15] += 1;
      		    sa.sin6_addr.s6_addr[14] += 1;
      		    sa.sin6_addr.s6_addr[13] += 1;
      		    sa.sin6_addr.s6_addr[12] += 1;
      		    sa.sin6_addr.s6_addr[11] += 1;
		} 
		else if ( flag[10]) 
		{
      		    sa.sin6_addr.s6_addr[15] += 1;
      		    sa.sin6_addr.s6_addr[14] += 1;
      		    sa.sin6_addr.s6_addr[13] += 1;
      		    sa.sin6_addr.s6_addr[12] += 1;
      		    sa.sin6_addr.s6_addr[11] += 1;
		    sa.sin6_addr.s6_addr[10] += 1;
		}  
		else if ( flag[9]) 
		{
      		    sa.sin6_addr.s6_addr[15] += 1;
      		    sa.sin6_addr.s6_addr[14] += 1;
      		    sa.sin6_addr.s6_addr[13] += 1;
      		    sa.sin6_addr.s6_addr[12] += 1;
      		    sa.sin6_addr.s6_addr[11] += 1;
		    sa.sin6_addr.s6_addr[10] += 1;
		    sa.sin6_addr.s6_addr[9]  += 1;
		} 
		else if ( flag[8]) 
		{
      		    sa.sin6_addr.s6_addr[15] += 1;
      		    sa.sin6_addr.s6_addr[14] += 1;
      		    sa.sin6_addr.s6_addr[13] += 1;
      		    sa.sin6_addr.s6_addr[12] += 1;
      		    sa.sin6_addr.s6_addr[11] += 1;
		    sa.sin6_addr.s6_addr[10] += 1;
		    sa.sin6_addr.s6_addr[9]  += 1;
                    sa.sin6_addr.s6_addr[8]  += 1;
		} 
		else 
		{ 
   		    sa.sin6_addr.s6_addr[15] += 1;
     		}
 		inet_ntop(AF_INET6,  &(sa.sin6_addr),str, INET6_ADDRSTRLEN);
  		destIpAddress.push(str);
  		//printf("%s\n", str);
    	    }
   	} 
    }
};


class getService 
{
   public:
     	char buffer[BUFFER_SIZE];
     	map<int,string> selectedPortMap;
     	int sockfd;
     	int recvData;
     	string message;
     	string ipAddress;
     	//char bufferChtoIn[MAX_INT_BYTE+1]; //Integer size 32 bit
     
	//public:
     	getService() 
	{
            memset(buffer,0,BUFFER_SIZE);
            selectedPortMap[80]  = "HTTP";
            selectedPortMap[22]  = "SSH";
            selectedPortMap[25]  = "SMTP";
            selectedPortMap[43]  = "WHOIS";
            selectedPortMap[110] = "POP3";
            selectedPortMap[143] = "IMAP"; 
            sockfd = -1;
            recvData = -1;
            ipAddress = "127.0.0.1";
            message=" ";
            //memset(bufferChtoIn,0,MAX_INT_BYTE+1);
        }
     	getService(string ip ) 
	{
      	    if ( !ip.empty())
            ipAddress = ip;
        }
     
	string getIp() 
	{ 
	    return ipAddress; 
	}

     	~getService() 
	{ 
       	    if ( sockfd != -1 )
            close(sockfd);
     	} 

     	string getServiceName(int portNum) 
	{
            try 
	    {
           	return this->selectedPortMap[portNum];
            } 
	    catch( char *str) 
	    {
           	return "NULL";
       	}
    }
    
    getService operator=( string ip ) 
    {
     	if ( ip.empty())
           return *this;
     	return getService(ip);
    }

    string getIpAddress() 
    {
    	return this->ipAddress;
    }

    int sndRcvData() 
    {
    	fd_set fds;
    	struct timeval tv;  
    	send(sockfd,message.c_str(),strlen(message.c_str())+1,MSG_OOB);
    	FD_ZERO(&fds);
    	FD_SET(sockfd, &fds);
    	tv.tv_sec = 5;
    	tv.tv_usec = 0;
    	int selectStatus = select(sockfd+1, &fds, NULL, NULL, &tv);

    	if ( selectStatus !=0 && selectStatus != -1 )
     	    return recv(sockfd, buffer,BUFFER_SIZE, 0);
    	if ( selectStatus == 0 ) 
            cerr << "Time out occured \n";
    	else if ( selectStatus == -1 ) 
            cerr << "Error with select\n";

    	return NODATA;
   }

   int createConn(int port) 
   {
      	struct addrinfo hints , *conn;
      	memset(&hints, 0, sizeof hints);
      	hints.ai_family = AF_UNSPEC;
      	hints.ai_socktype = SOCK_STREAM;
      	char portC[MAX_INT_BYTE] = {0};
      	int count = MAX_INT_BYTE - 1;
      	do  
	{
       	    portC[--count] = ( port % 10 ) + '0';   
      	} while(port /= BASE );
      
	portC[MAX_INT_BYTE-1] = '\0';
      	//cout << portC+count;
      	getaddrinfo(ipAddress.c_str(),portC+count,&hints, &conn);
      	sockfd = socket(conn->ai_family, conn->ai_socktype, conn->ai_protocol);
      	//fcntl(sockfd, F_SETFL, FNONBLOCK);
      	int connectStatus = connect(sockfd, conn->ai_addr, conn->ai_addrlen);    
      	freeaddrinfo(conn);
      	return connectStatus;
   }
   
   string testSSH() 
   {
   	createConn(SSH);
   	message  = message + "ssh -v" +  " " + ipAddress;
   	recvData = sndRcvData();

   	//analyse buffer
   	if ( recvData > NODATA ) 
	{
            buffer[recvData] = '\0';
            //cout << buffer ;
            return string(buffer);
      	}  else
              return string("N/A"); 
     	//SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1             
   }

   string testHTTP() 
   {
      	createConn(HTTP);
      	message = message + ipAddress + " HTTP/1.1\n\n";//get request
      	recvData = sndRcvData();
      	if ( recvData > NODATA ) 
	{
            //cout << buffer << endl;
      	    buffer[recvData] = '\0';
      	    //cout << buffer << endl;
     	    char *ptr;
     	    if ( ( ptr = strstr(buffer,"HTTP/1.1")) != NULL)
	    { 
         	return string("HTTP/1.1"); //update in hashMap
	    }
            else if ( (ptr = strstr(buffer,"HTTP/1.0" )) != NULL )
	    {
         	return string("HTTP/1.0");//update version
	    }
     	    else if ( (ptr = strstr(buffer,"<address>")) != NULL ) 
	    {    
        	char *ptr1 = strstr(buffer,"server");
		//WHERE
            	if ( ptr1 != NULL   ) 
	    	{
            	   int vsize = 64;
             	    char version[vsize];
                    strncpy(version,ptr+strlen("<address>"),12);
                    version[12]='\0';
             	    //cout << version << endl;
             	    return string(version);
       	    	}
    	    }
    	    else
       		return string("N/A");  
      	//<address>Apache/2.2.22 (Ubuntu) Server at 127.0.1.1 Port 80</address> strxfrm
     	}  else
              return string("N/A");
   }
       
   string testPOP3() 
   {
   	createConn(POP3);
     	message = "";
     	recvData = sndRcvData();
     	if ( recvData > NODATA ) 
	{
      	    buffer[recvData] = '\0';
            //cout << buffer << endl;
            char *ptr;
            if ((ptr = strstr(buffer,"+OK")) != NULL )
         	return string("POP3 OK");
    	} else
              return string("N/A");
   }

   string testWHOIS() 
   {
   	createConn(WHOIS);
     	message = "whois --version ";
     	recvData = sndRcvData();
     	if ( recvData > NODATA ) 
	{
      	    buffer[recvData] = '\0';
     	    //cout << buffer << endl;
            return string("N/A");
     	} else
              return string("N/A"); 
   }

   string testSMTP() 
   {
     	createConn(SMTP);
     	message = "";
     	recvData = sndRcvData();
     	if ( recvData > 0 ) 
	{
      	    buffer[recvData] = '\0';
      	    //cout << buffer << endl; 
            char *ptr;
            if (( ptr = strstr(buffer,"Sendmail")) != NULL ) 
	    {
          	ptr = ptr + strlen("Sendmail");
          	char *ptr1 = strchr(ptr,'/');
          	char version[24];
          	strncpy(version,ptr,14);
                version[14] = '\0';
          	return string(buffer);
            }
     	} else
              return string("N/A");
   }

   string testIMAP() 
   {
     	createConn(IMAP);
     	message = "fetch 1";
     	recvData = sndRcvData();
     	if ( recvData > NODATA ) 
	{
      	    buffer[recvData] = '\0'; 
     		/*
       			telnet localhost 143
       			* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE STARTTLS AUTH=PLAIN] Dovecot ready.
     		*/
    	    char *pch;
    	    if ( (pch = strstr(buffer,"IMAP4")) != NULL )
        	return string("IMAP4");
    	    else if  ( (pch = strstr(buffer,"IMAP2")) != NULL )
        	return string("IMAP2");
    	    else if  ( (pch = strstr(buffer,"IMAP3")) != NULL )
        	return string("IMAP3");
    	    else 
        	return string("N/A");
    		//cout << buffer << endl;
    	} else
              return string("N/A");
   }
      
};

class buildTcpHeader 
{
  public:
      	struct ps_tcphdr *mytcphdr;
      	map<string,u_int8_t> tcpflags;
      	static const int src_port = 6679;
  	//public:
    	buildTcpHeader() 
	{
      	    mytcphdr = new struct ps_tcphdr[TCPHEADER_SIZE];
	    tcpflags["FIN"] =  TH_FIN;
      	    tcpflags["NULL"] = TH_NULL;
      	    tcpflags["XMAS"] = TH_FIN|TH_PUSH|TH_URG;
      	    tcpflags["ACK"]  = TH_ACK;
            tcpflags["SYN"]  = TH_SYN;
   	}
   	~buildTcpHeader() 
	{ 
            delete[] mytcphdr; 
	}

   	struct ps_tcphdr* getTcpHeader() 
	{
       	    return this->mytcphdr;
   	}


 	void setTcpHeader(string scanOptions,int dst_port , bool ifUrgPtr = false) 
	{
      	     map<string,u_int8_t >::iterator pstcp;
      	     pstcp = tcpflags.find(scanOptions);
             mytcphdr->th_seq          = htonl(rand());
      	     mytcphdr->th_ack          = 0;
      	     mytcphdr->th_win          = htons(TCP_MAXWIN);
      	     mytcphdr->th_off          = 0x50;
      	     mytcphdr->th_sport	= htons(src_port);
      	     mytcphdr->th_dport	= htons(dst_port);
      	     mytcphdr->th_sum          = 0;
      	     mytcphdr->th_urp          = 0;
      	     mytcphdr->th_flags        = pstcp->second;
      	    //mytcphdr->th_flags        =  TH_SYN;
   	} 
  	// friend uint16_t Checksum(unsigned char *, size_t );
};

class buildIpHeader 
{
    public:
      	struct ps_iphdr *myiphdr;
        buildIpHeader() 
	{
            myiphdr= new struct ps_iphdr[IPHEADER_SIZE];
            myiphdr->ip_vhl    = 0x45;
	    myiphdr->ip_tos    = 0;
	    myiphdr->ip_off    = 0;
            myiphdr->ip_id     = htonl(363);;
            myiphdr->ip_ttl    = 64;
	    myiphdr->ip_sum    = 0;   
	}

        ~buildIpHeader() 
	{ 
	    delete[] myiphdr; 
	}

	struct ps_iphdr *getIpHeader() 
	{
            return this->myiphdr;
       	}

        void setIpHeader(string srcIp , string dstIp , u_int8_t ip_p) 
	{
            if ( ip_p == IPPROTO_TCP )
             	myiphdr->ip_len    = (IPHEADER_SIZE+TCPHEADER_SIZE);
            else if ( ip_p == IPPROTO_UDP)
              	myiphdr->ip_len    = (IPHEADER_SIZE+UDPHEADER_SIZE);
            else if ( ip_p == IPPROTO_ICMP )
             	myiphdr->ip_len = (IPHEADER_SIZE+ICMPHEADER_SIZE);
            else
             	myiphdr->ip_len = IPHEADER_SIZE;

             myiphdr->ip_p      = ip_p; 
             inet_pton(AF_INET, srcIp.c_str(), (void *)(&myiphdr->ip_src));
             //inet_pton(AF_INET, "127.0.0.1", (void *)(&myiphdr->ip_src));    
             inet_pton(AF_INET, dstIp.c_str(), (void *)(&myiphdr->ip_dst));
      	}
     	//  friend uint16_t Checksum(unsigned char *, size_t );
};


class buildUdpHeader 
{
    public:
        struct ps_udphdr *myudphdr;
        static const int src_port = 7689;
    	buildUdpHeader() 
	{
            myudphdr= new struct ps_udphdr[UDPHEADER_SIZE];
            myudphdr->uh_ulen = htons(UDPHEADER_SIZE);
            myudphdr->uh_sum = 0;
    	}    

    	~buildUdpHeader() 
	{ 
	    delete[] myudphdr; 
	}

    	void setUdpHeader(int dst_port ) 
	{
      	     myudphdr->uh_sport	= htons(src_port);
             myudphdr->uh_dport	= htons(dst_port);
     	}

   	struct ps_udphdr *getUdpHeader() 
	{
            return this->myudphdr;
       	}
 };

class buildIp6Header //rfc 3493
{
    public :
       	struct ps_ip6hdr *myip6hdr;
     	buildIp6Header() 
	{
            myip6hdr= new struct ps_ip6hdr[IPV6HEADER_SIZE];
            int flags = 0x60;
	    memcpy(myip6hdr->ip6_flags,&flags,sizeof(int));
            myip6hdr->ip6_hl = HOP_LIMIT; 
        }
     	~buildIp6Header() 
	{ 
	    delete[] myip6hdr; 
	} 
 
	void setIp6Header(string srcIp, string dstIp, u_int8_t ip_p)
	{
	     if ( ip_p == IPPROTO_TCP )
             	myip6hdr->ip6_len    = (IPV6HEADER_SIZE+TCPHEADER_SIZE);
             else if ( ip_p == IPPROTO_UDP)
             	myip6hdr->ip6_len    = (IPV6HEADER_SIZE+UDPHEADER_SIZE);
             else
	     	myip6hdr->ip6_len = IPV6HEADER_SIZE;
	
	     myip6hdr->ip6_nxthdr = ip_p;
	     inet_pton(AF_INET6, srcIp.c_str(), (void *)(&myip6hdr->ip6_src));
             inet_pton(AF_INET6, dstIp.c_str(), (void *)(&myip6hdr->ip6_dst));	
	}

	struct ps_ip6hdr *getIp6Header()
	{
	    return this->myip6hdr;
	}
};


