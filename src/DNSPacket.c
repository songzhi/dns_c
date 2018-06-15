#include "DNSPacket.h"

/*
 * This will convert www.baidu.com to 3www5baidu3com
 * */
void changeToDnsNameFormat(unsigned char *des, const unsigned char *host) {
  int lock = 0, i;
  int host_len = strlen((char *) host);
  unsigned char *_host =
          (unsigned char *) malloc(sizeof(unsigned char) * host_len);
  strcpy((char *) _host, (char *) host);
  strcat((char *) _host, ".");
  for (i = 0; i < host_len + 1; i++) {
    if (_host[i] == '.') {
      *des++ = i - lock;
      for (; lock < i; lock++) {
        *des++ = _host[lock];
      }
      lock++; // or lock=i+1;
    }
  }
  *des++ = '\0';
}

void readDNSPacket(unsigned char *buf, DNS_Packet *packet) {
  unsigned char *_buf = (unsigned char *) malloc(65536);
  memcpy(_buf, buf, 65536);
  buf = _buf;
  DNS_Header *dns_header = (DNS_Header *) buf;
  packet->Header = dns_header;
  packet->Answer_RRs =
          (ResRecord *) malloc(sizeof(ResRecord) * ntohs(dns_header->answerCount));
  packet->Authority_RRs = (ResRecord *) malloc(
          sizeof(ResRecord) * ntohs(dns_header->authorityCount));
  packet->Additional_RRs = (ResRecord *) malloc(
          sizeof(ResRecord) * ntohs(dns_header->additionalCount));

  // move ahead of the dns header and read the query field
  unsigned char *reader = &buf[sizeof(DNS_Header)];
  Query *queries =
          (Query *) malloc(sizeof(Query) * ntohs(dns_header->queryCount));
  int stop = 0;
  for (int i = 0; i < ntohs(dns_header->queryCount); i++) {
    queries[i].name = readDomainName(reader, buf, &stop);
    reader += stop;
    queries[i].question = (Question *) (reader);
    reader += sizeof(Question);
  }
  packet->Questions = queries;

  // read answers
  ResRecord *answers = packet->Answer_RRs;
  for (int i = 0; i < ntohs(dns_header->answerCount); i++) {
    answers[i].name = readDomainName(reader, buf, &stop);
    reader += stop;

    answers[i].resource = (R_Data *) (reader);
    reader += sizeof(R_Data);

    if (ntohs(answers[i].resource->type) == Q_T_A) {
      answers[i].rdata =
              (unsigned char *) malloc(ntohs(answers[i].resource->data_len));

      for (int j = 0; j < ntohs(answers[i].resource->data_len); j++) {
        answers[i].rdata[j] = reader[j];
      }

      answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

      reader = reader + ntohs(answers[i].resource->data_len);
    } else if (ntohs(answers[i].resource->type) == Q_T_MX) {
      answers[i].rdata = (unsigned char *) malloc(sizeof(unsigned char) * 256);
      answers[i].rdata[0] = reader[0];
      answers[i].rdata[1] = reader[1]; // 前两个字节是preference字段
      strcpy((char *) answers[i].rdata + 2,
             (const char *) readDomainName(reader + 2, buf, &stop));
      reader = reader + stop + 2;
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

    auth[i].resource = (R_Data *) (reader);
    reader += sizeof(R_Data);

    auth[i].rdata = readDomainName(reader, buf, &stop);
    reader += stop;
  }

  // read additional
  ResRecord *addit = packet->Additional_RRs;
  for (int i = 0; i < ntohs(dns_header->additionalCount); i++) {
    addit[i].name = readDomainName(reader, buf, &stop);
    reader += stop;

    addit[i].resource = (R_Data *) (reader);
    reader += sizeof(R_Data);

    if (ntohs(addit[i].resource->type) == Q_T_A) {
      addit[i].rdata =
              (unsigned char *) malloc(ntohs(addit[i].resource->data_len));
      for (int j = 0; j < ntohs(addit[i].resource->data_len); j++)
        addit[i].rdata[j] = reader[j];

      addit[i].rdata[ntohs(addit[i].resource->data_len)] = '\0';
      reader += ntohs(addit[i].resource->data_len);
    } else {
      addit[i].rdata = readDomainName(reader, buf, &stop);
      reader += stop;
    }
  }
  packet->data_len = reader - buf;
}

void printPacket(DNS_Packet *packet) {
  // print answers

  DNS_Header *dns_header = packet->Header;
  printf("Packet:  ");
  switch (dns_header->rcode) {
    case 0:
      printf("status:OK");
      break;
    case 1:
      printf("status:查询格式错误");
      break;
    case 2:
      printf("status:服务器内部错误");
      break;
    case 3:
      printf("status:名字不存在");
      break;
  }
  switch (dns_header->rd) {
    case 0:
      printf(" 非递归查询\n");
      break;
    case 1:
      printf(" 递归查询\n");
      break;
  }

  Query *queries = packet->Questions;
  printf("Queries : %d \n", ntohs(dns_header->queryCount));
  for (int i = 0; i < ntohs(dns_header->queryCount); i++) {
    printf("  Name:%s Type:%d \n", queries[i].name,
           ntohs(queries[i].question->qtype));
  }

  ResRecord *answers = packet->Answer_RRs;
  printf("Answer Records : %d \n", ntohs(dns_header->answerCount));
  for (int i = 0; i < ntohs(dns_header->answerCount); i++) {
    printf("  Name : %s ", answers[i].name);

    if (ntohs(answers[i].resource->type) == Q_T_A) {
      long *p;
      p = (long *) answers[i].rdata;
      struct sockaddr_in a;
      a.sin_addr.s_addr = (*p); // working without ntohl
      printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
    }

    if (ntohs(answers[i].resource->type) == Q_T_MX) {
      // Canonical name for an alias
      printf("has mail exchange : %s（preference: %d）", answers[i].rdata + 2,
             ntohs(*(unsigned short *) answers[i].rdata));
    }

    if (ntohs(answers[i].resource->type) == Q_T_CNAME) {
      // Canonical name for an alias
      printf("has alias name : %s", answers[i].rdata);
    }

    printf("\n");
  }

  // print authorities
  ResRecord *auth = packet->Authority_RRs;
  printf("Authoritive Records : %d \n", ntohs(dns_header->authorityCount));
  for (int i = 0; i < ntohs(dns_header->authorityCount); i++) {

    printf("  Name : %s ", auth[i].name);
    if (ntohs(auth[i].resource->type) == 2) {
      printf("has nameserver : %s", auth[i].rdata);
    }
    printf("\n");
  }

  // print additional resource records
  ResRecord *addit = packet->Additional_RRs;
  printf("Additional Records : %d \n", ntohs(dns_header->additionalCount));
  for (int i = 0; i < ntohs(dns_header->additionalCount); i++) {
    printf("  Name : %s ", addit[i].name);
    if (ntohs(addit[i].resource->type) == 1) {
      long *p;
      p = (long *) addit[i].rdata;
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
  unsigned int p = 0;
  int i, j;
  *count = (int) strlen((const char *) reader) + 1;

  name = (unsigned char *) malloc(256);
  strcpy((char *) name, (const char *) reader);

  // now convert 3www5baidu3com0 to www.baidu.com
  for (i = 0; i < (int) strlen((const char *) name); i++) {
    p = name[i];
    for (j = 0; j < (int) p; j++) {
      name[i] = name[i + 1];
      i = i + 1;
    }
    name[i] = '.';
  }
  name[i - 1] = '\0'; // remove the last dot
  return name;
}
