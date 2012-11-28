

#ifndef _PACKETS_H
#define _PACKETS_H

#include <netinet/ip_icmp.h>
#define ZEROSIZE 3
struct ps_iphdr
{
    u_int8_t ip_vhl;			/*version and header length*/
    u_int8_t ip_tos;			/* type of service */
    u_short ip_len;			/* total length */
    u_short ip_id;			/* identification */
    u_short ip_off;			/* fragment offset field */
    #define	IP_RF 0x8000			/* reserved fragment flag */
    #define	IP_DF 0x4000			/* dont fragment flag */
    #define	IP_MF 0x2000			/* more fragments flag */
    #define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    u_int8_t ip_ttl;			/* time to live */
    u_int8_t ip_p;			/* protocol */
    u_short ip_sum;			/* checksum */
    struct in_addr ip_src, ip_dst;	/* source and dest address */
};

#define	IPVERSION	4               /* IP version number */
#define	IP_MAXPACKET	65535		/* maximum packet size */
#define	MAXTTL		255		/* maximum time to live (seconds) */
#define	IPDEFTTL	64		/* default ttl, from RFC 1340 */
#define	IPFRAGTTL	60		/* time to live for frags, slowhz */
#define	IPTTLDEC	1		/* subtracted when forwarding */

#define	IP_MSS		576		/* default maximum segment size */

# define TCP_MAXWIN	65535
#  define TH_FIN	0x01
#  define TH_SYN	0x02
#  define TH_RST	0x04
#  define TH_PUSH	0x08
#  define TH_ACK	0x10
#  define TH_URG	0x20
#  define TH_NULL       0x00
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define TH_OFF(th)      (((th)->th_off & 0xf0) >> 4)

typedef	u_int32_t tcp_seq;
struct ps_tcphdr
{
    u_int16_t th_sport;		/* source port */
    u_int16_t th_dport;		/* destination port */
    tcp_seq th_seq;		/* sequence number */
    tcp_seq th_ack;		/* acknowledgement number */
    u_char th_off;
    u_int8_t th_flags;

    u_int16_t th_win;		/* window */
    u_int16_t th_sum;		/* checksum */
    u_int16_t th_urp;		/* urgent pointer */
};

struct ps_pseudohdr 
{
    u_int32_t saddr;
    u_int32_t daddr;
    u_char zero;
    u_char protocol;
    u_int16_t length;
};

struct ps_ip6hdr
{
    u_int8_t ip6_flags[4];	/*  4 bits version, 8 bits Traffic Class, 20 bits flow-id */
    u_int8_t ip6_nxthdr;	/* next header */
    u_int16_t ip6_len;		 /* payload length */
    u_int8_t ip6_hl;		 /* hop limit */	
    struct in6_addr ip6_src;      /* source address */
    struct in6_addr ip6_dst;      /* destination address */
};

//flylib.com/books/en/2.223.1.53/1/
struct ps_pseudo6hdr
{
    u_int32_t payloadlength;
    u_int8_t zero[ZEROSIZE];
    u_int8_t next;
    struct in6_addr ip6_src;
    struct in6_addr ip6_dst;
};

//http://www.tcpipguide.com/free/t_TCPChecksumCalculationandtheTCPPseudoHeader-2.htm
struct ps_udphdr
{
  u_int16_t uh_sport;		/* source port */
  u_int16_t uh_dport;		/* destination port */
  u_int16_t uh_ulen;		/* udp length */
  u_int16_t uh_sum;		/* udp checksum */
};

#endif
