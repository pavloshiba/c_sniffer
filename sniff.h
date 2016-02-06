#ifndef SNIFF_H
#define SNIFF_H
/*
Header file for test task
Platform        Linux (kernel 3.19) – Ubuntu 14.04 LTS
*/
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>    //Provides declarations for icmp header
#include <netinet/udp.h>       //Provides declarations for udp header
#include <netinet/tcp.h>       //Provides declarations for tcp header
#include <netinet/ip.h>        //Provides declarations for ip header
#include <string.h>

extern FILE *logfile;
extern struct sockaddr_in source,dest;

// packets count
extern int  total;
extern int  icmp_c;
extern int  igmp;
extern int  tcp;
extern int  udp;
extern int  others;

//callback  to pcap_loop that proccess packets
void callback(u_char *useless,const struct pcap_pkthdr* pkthdr, const u_char* buffer);

void print_ethernet_header(const u_char *buffer, int size);
void print_ip_header(const u_char * buffer, int Size);
void print_tcp_packet(const u_char * buffer, int size);
void print_udp_packet(const u_char *buffer , int size);
void print_icmp_packet(const u_char * buffer , int size);
void print_data (const u_char * data , int size);


#endif // SNIFF_H
