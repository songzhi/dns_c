#ifndef DNS_PACKET_INCLUDED
#define DNS_PACKET_INCLUDED

#include <arpa/inet.h> //inet_addr , inet_ntoa , ntohs etc
#include <netinet/in.h>
#include <stdio.h>  //printf
#include <stdlib.h> //malloc
#include <string.h> //strlen
#include <sys/socket.h>
#include <unistd.h> //getpid

#define Q_T_A 1     // Ipv4 address
#define Q_T_NS 2    // Nameserver
#define Q_T_CNAME 5 // Canonical name
#define Q_T_SOA 6   // Start of authority zone
#define Q_T_PTR 12  // Domain name pointer
#define Q_T_MX 15   // Mail server
#define T_IN 1 // Internet
#define TTL 360
#define ROOT_SERVER_HOST "127.0.0.2"


// Constant sized fields of the resource record structure
#pragma pack(push, 1)
typedef struct R_Data {
  unsigned short type;
  unsigned short _class;
  unsigned int ttl;
  unsigned short data_len;
} R_Data;
#pragma pack(pop)

// Pointers to resource record contents
typedef struct ResRecord {
  /*
   * 这里的name有两种表达方式,一种是直接数据，一种是压缩指针
   */
  unsigned char *name;
  R_Data *resource;
  unsigned char *rdata;
} ResRecord;

typedef struct DNS_Header {
  unsigned short id;
  unsigned char rd : 1;     // recursion desired
  unsigned char tc : 1;     // truncated message
  unsigned char aa : 1;     // authoritive answer
  unsigned char opcode : 4; // purpose of message,usually being 0
  unsigned char qr : 1;     // 0:query/1:response

  unsigned char rcode : 4; // response code,0 represent correct,otherwise 1
  unsigned char cd : 1;    // checking disabled,must be zero
  unsigned char ad : 1;    // authenticated data,must be zero
  unsigned char z : 1;     // its z! reserved,must be zero
  unsigned char ra : 1;    // recursion available
  unsigned short queryCount;
  unsigned short answerCount;
  unsigned short authorityCount;
  unsigned short additionalCount;
} DNS_Header;

// Constant sized fields of query structure
typedef struct Question {
  unsigned short qtype;  // query type
  unsigned short qclass; // query class
} Question;

// Structure of a Query
typedef struct Query {
  unsigned char *name;
  Question *question;
} Query;

typedef struct DNS_Packet {
  DNS_Header *Header;
  Query *Questions;
  ResRecord *Answer_RRs;
  ResRecord *Authority_RRs;
  ResRecord *Additional_RRs;
  int data_len;
} DNS_Packet;


unsigned char *readDomainName(unsigned char *reader, unsigned char *buffer,
                              int *count);
void readDNSPacket(unsigned char *buf, DNS_Packet *packet);
int addQuery(unsigned char *reader, Query *query);
int addResRecord(unsigned char *reader, ResRecord *resRecord);
void changeToDnsNameFormat(unsigned char *des, const unsigned char *host);
void printPacket(DNS_Packet *packet);

#endif
