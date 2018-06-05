#include "DataStructure.h"

int main(void) {
  unsigned char hostname[100];
  printf("Enter Hostname to Lookup : ");
  scanf("%s", hostname);
  unsigned char buf[65536];
  int data_len = setDNSPacket(buf, hostname, Q_T_A);
  sendPacketAndGetResult(buf, data_len);
  DNS_Packet packet;
  readDNSPacket(buf, &packet);
  printPacket(&packet);
  return 0;
}

void setDNSHeader(DNS_Header *header, uint16_t queryCount, uint16_t answerCount,
                  uint16_t authorCount, uint16_t additionCount) {
  header->id = (unsigned short)htons(getpid());
  header->qr = 0;     // This is a query
  header->opcode = 0; // This is a standard query
  header->aa = 0;     // Not Authoritative
  header->tc = 0;     // This message is not truncated
  header->rd = 1;     // Recursion Desired
  header->ra = 0;     // Recursion not available
  header->z = 0;
  header->ad = 0;
  header->cd = 0;
  header->rcode = 0;
  header->queryCount = htons(queryCount);
  header->answerCount = htons(answerCount);
  header->authorityCount = htons(authorCount);
  header->additionalCount = htons(additionCount);
}

/*
 * This will convert www.baidu.com to 3www5baidu3com
 * */
void changeToDnsNameFormat(unsigned char *dns, unsigned char *host) {
  int lock = 0, i;
  strcat((char *)host, ".");

  for (i = 0; i < strlen((char *)host); i++) {
    if (host[i] == '.') {
      *dns++ = i - lock;
      for (; lock < i; lock++) {
        *dns++ = host[lock];
      }
      lock++; // or lock=i+1;
    }
  }
  *dns++ = '\0';
}

int addQuery(unsigned char *reader, unsigned char *host, int query_type) {
  unsigned char *qname = reader;
  changeToDnsNameFormat(qname, host);
  int qname_len = strlen((const char *)qname) + 1;
  Question *qinfo = (Question *)&reader[qname_len];
  qinfo->qtype =
      htons(query_type);    // type of the query , A , MX , CNAME , NS etc
  qinfo->qclass = htons(1); // internet
  return qname_len + (int)sizeof(Question);
}

int setDNSPacket(unsigned char *buf, unsigned char *host, int query_type) {
  DNS_Header *dns_header = (DNS_Header *)buf;
  setDNSHeader(dns_header, 1, 0, 0, 0);
  int ques_len = addQuery(&buf[sizeof(DNS_Header)],host,query_type);
  
  return (int)sizeof(DNS_Header) + ques_len;
}

void sendPacketAndGetResult(unsigned char *buf, int data_len) {
  struct sockaddr_in dest;
  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  dest.sin_family = AF_INET;
  dest.sin_port = htons(53);
  dest.sin_addr.s_addr = inet_addr("208.67.222.222");
  printf("\nSending Packet...");
  if (sendto(sock, (char *)buf, data_len, 0, (struct sockaddr *)&dest,
             sizeof(dest)) < 0) {
    perror("sendto failed");
  }
  printf("Done");
  int i = sizeof dest;
  printf("\nReceiving answer...");
  if (recvfrom(sock, (char *)buf, 65536, 0, (struct sockaddr *)&dest,
               (socklen_t *)&i) < 0) {
    perror("recvfrom failed");
  }
  printf("Done");
}

void readDNSPacket(unsigned char *buf, DNS_Packet *packet) {
  DNS_Header *dns_header = (DNS_Header *)buf;
  packet->Header = dns_header;
  packet->Questions = (Query *)&buf[sizeof(DNS_Header)];
  packet->Answer_RRs =
      (ResRecord *)malloc(sizeof(ResRecord) * ntohs(dns_header->answerCount));
  packet->Authority_RRs = (ResRecord *)malloc(
      sizeof(ResRecord) * ntohs(dns_header->authorityCount));
  packet->Additional_RRs = (ResRecord *)malloc(
      sizeof(ResRecord) * ntohs(dns_header->additionalCount));
  // move ahead of the dns header and the query field
  unsigned char *reader = &buf[sizeof(DNS_Header)];
  for (int i = 0; i < ntohs(dns_header->queryCount); i++) {
    reader += strlen((const char *)reader) + 1 + sizeof(Question);
  }
  int stop = 0;

  ResRecord *answers = packet->Answer_RRs;
  for (int i = 0; i < ntohs(dns_header->answerCount); i++) {
    answers[i].name = readDomainName(reader, buf, &stop);
    reader += stop;

    answers[i].resource = (R_Data *)(reader);
    reader += sizeof(R_Data);

    if (ntohs(answers[i].resource->type) == 1) // if its an ipv4 address
    {
      answers[i].rdata =
          (unsigned char *)malloc(ntohs(answers[i].resource->data_len));

      for (int j = 0; j < ntohs(answers[i].resource->data_len); j++) {
        answers[i].rdata[j] = reader[j];
      }

      answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

      reader = reader + ntohs(answers[i].resource->data_len);
    } else {
      answers[i].rdata = readDomainName(reader, buf, &stop);
      reader = reader + stop;
    }
  }

  // read authorities
  ResRecord *auth = packet->Authority_RRs;
  for (int i = 0; i < ntohs(dns_header->authorityCount); i++) {
    auth[i].name = readDomainName(reader, buf, &stop);
    reader += stop;

    auth[i].resource = (R_Data *)(reader);
    reader += sizeof(R_Data);

    auth[i].rdata = readDomainName(reader, buf, &stop);
    reader += stop;
  }

  // read additional
  ResRecord *addit = packet->Additional_RRs;
  for (int i = 0; i < ntohs(dns_header->additionalCount); i++) {
    addit[i].name = readDomainName(reader, buf, &stop);
    reader += stop;

    addit[i].resource = (R_Data *)(reader);
    reader += sizeof(R_Data);

    if (ntohs(addit[i].resource->type) == 1) {
      addit[i].rdata =
          (unsigned char *)malloc(ntohs(addit[i].resource->data_len));
      for (int j = 0; j < ntohs(addit[i].resource->data_len); j++)
        addit[i].rdata[j] = reader[j];

      addit[i].rdata[ntohs(addit[i].resource->data_len)] = '\0';
      reader += ntohs(addit[i].resource->data_len);
    } else {
      addit[i].rdata = readDomainName(reader, buf, &stop);
      reader += stop;
    }
  }
}

void printPacket(DNS_Packet *packet) {
  // print answers
  ResRecord *answers = packet->Answer_RRs;
  DNS_Header *dns_header = packet->Header;

  printf("\nAnswer Records : %d \n", ntohs(dns_header->answerCount));
  for (int i = 0; i < ntohs(dns_header->answerCount); i++) {
    printf("Name : %s ", answers[i].name);

    if (ntohs(answers[i].resource->type) == Q_T_A) // IPv4 address
    {
      long *p;
      p = (long *)answers[i].rdata;
      struct sockaddr_in a;
      a.sin_addr.s_addr = (*p); // working without ntohl
      printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
    }

    if (ntohs(answers[i].resource->type) == 5) {
      // Canonical name for an alias
      printf("has alias name : %s", answers[i].rdata);
    }

    printf("\n");
  }

  // print authorities
  ResRecord *auth = packet->Authority_RRs;
  printf("\nAuthoritive Records : %d \n", ntohs(dns_header->authorityCount));
  for (int i = 0; i < ntohs(dns_header->authorityCount); i++) {

    printf("Name : %s ", auth[i].name);
    if (ntohs(auth[i].resource->type) == 2) {
      printf("has nameserver : %s", auth[i].rdata);
    }
    printf("\n");
  }

  // print additional resource records
  ResRecord *addit = packet->Additional_RRs;
  printf("\nAdditional Records : %d \n", ntohs(dns_header->additionalCount));
  for (int i = 0; i < ntohs(dns_header->additionalCount); i++) {
    printf("Name : %s ", addit[i].name);
    if (ntohs(addit[i].resource->type) == 1) {
      long *p;
      p = (long *)addit[i].rdata;
      struct sockaddr_in a;
      a.sin_addr.s_addr = (*p);
      printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
    }
    printf("\n");
  }
}

unsigned char *readDomainName(unsigned char *reader, unsigned char *buffer,
                              int *count) {
  unsigned char *name;
  unsigned int p = 0, jumped = 0, offset;
  int i, j;

  *count = 1;
  name = (unsigned char *)malloc(256);

  name[0] = '\0';

  // read the names in 3www5baidu3com format
  while (*reader != 0) {
    if (*reader >= 192) {
      // 对于出现过的name采用压缩指针的方式
      // 49152 = 11000000 00000000
      offset = (*reader) * 256 + *(reader + 1) - 49152;
      reader = buffer + offset - 1;
      jumped = 1;
    } else {
      name[p++] = *reader;
    }

    reader = reader + 1;
    if (jumped == 0) {
      *count = *count + 1;
    }
  }

  name[p] = '\0';
  if (jumped == 1) {
    *count = *count + 1;
  }

  // now convert 3www5baidu3com0 to www.baidu.com
  for (i = 0; i < (int)strlen((const char *)name); i++) {
    p = name[i];
    for (j = 0; j < (int)p; j++) {
      name[i] = name[i + 1];
      i = i + 1;
    }
    name[i] = '.';
  }
  name[i - 1] = '\0'; // remove the last dot
  return name;
}
