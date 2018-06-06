#include "DNSPacket.h"

uint16_t ntons(uint16_t __hostshort) {
  return __hostshort;
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

int addQuery(unsigned char *reader, Query *query, int is_client) {
  uint16_t (*trans_func)(uint16_t __hostshort);
  if (is_client) {
    trans_func = htons;
  } else {
    trans_func = ntons;
  }
  unsigned char *qname = reader;
  changeToDnsNameFormat(qname, query->name);
  int qname_len = strlen((const char *)qname) + 1;
  Question *qinfo = (Question *)&reader[qname_len];
  qinfo->qtype = trans_func(
      query->question->qtype); // type of the query , A , MX , CNAME , NS etc
  qinfo->qclass = trans_func(query->question->qclass); // internet
  return qname_len + (int)sizeof(Question);
}

int addResRecord(unsigned char *reader, ResRecord *resRecord) {
  unsigned char *name = reader;
  changeToDnsNameFormat(name, resRecord->name);
  int name_len = strlen((const char *)name) + 1;
  R_Data *r_data = (R_Data *)&reader[name_len];
  r_data->ttl = htonl(resRecord->resource->ttl);
  r_data->type = htons(resRecord->resource->type);
  r_data->data_len = htons(resRecord->resource->data_len);
  reader += name_len + sizeof(R_Data);
  memcpy(reader, resRecord->rdata, resRecord->resource->data_len);
  return name_len + sizeof(R_Data) + resRecord->resource->data_len;
}

void readDNSPacket(unsigned char *buf, DNS_Packet *packet) {
  DNS_Header *dns_header = (DNS_Header *)buf;
  packet->Header = dns_header;
  packet->Answer_RRs =
      (ResRecord *)malloc(sizeof(ResRecord) * ntohs(dns_header->answerCount));
  packet->Authority_RRs = (ResRecord *)malloc(
      sizeof(ResRecord) * ntohs(dns_header->authorityCount));
  packet->Additional_RRs = (ResRecord *)malloc(
      sizeof(ResRecord) * ntohs(dns_header->additionalCount));

  // move ahead of the dns header and read the query field
  unsigned char *reader = &buf[sizeof(DNS_Header)];
  Query *queries =
      (Query *)malloc(sizeof(Query) * ntohs(dns_header->queryCount));
  int stop = 0;
  for (int i = 0; i < ntohs(dns_header->queryCount); i++) {
    queries[i].name = readDomainName(reader, buf, &stop);
    reader += stop;
    queries[i].question = (Question *)(reader);
    reader += sizeof(Question);
  }
  packet->Questions = queries;

  // read answers
  ResRecord *answers = packet->Answer_RRs;
  for (int i = 0; i < ntohs(dns_header->answerCount); i++) {
    answers[i].name = readDomainName(reader, buf, &stop);
    reader += stop;

    answers[i].resource = (R_Data *)(reader);
    reader += sizeof(R_Data);

    if (ntohs(answers[i].resource->type) == Q_T_A) {
      answers[i].rdata =
          (unsigned char *)malloc(ntohs(answers[i].resource->data_len));

      for (int j = 0; j < ntohs(answers[i].resource->data_len); j++) {
        answers[i].rdata[j] = reader[j];
      }

      answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

      reader = reader + ntohs(answers[i].resource->data_len);
    } else if (ntohs(answers[i].resource->type) == Q_T_MX) {
      answers[i].rdata = (unsigned char *)malloc(sizeof(unsigned char) *256);
      answers[i].rdata[0] = reader[0];
      answers[i].rdata[1] = reader[1]; // 前两个字节是preference字段
      strcpy((char *)answers[i].rdata+2, (const char *)readDomainName(reader + 2, buf, &stop));
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

    if (ntohs(addit[i].resource->type) == Q_T_A) {
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

  DNS_Header *dns_header = packet->Header;

  if (dns_header->rcode == 1) {
    printf("Format Error");
  }

  Query *queries = packet->Questions;
  printf("\nQueries : %d \n", ntohs(dns_header->queryCount));
  for (int i = 0; i < ntohs(dns_header->queryCount); i++) {
    printf("  Name:%s Type:%d \n", queries[i].name,
           ntohs(queries[i].question->qtype));
  }

  ResRecord *answers = packet->Answer_RRs;
  printf("\nAnswer Records : %d \n", ntohs(dns_header->answerCount));
  for (int i = 0; i < ntohs(dns_header->answerCount); i++) {
    printf("  Name : %s ", answers[i].name);

    if (ntohs(answers[i].resource->type) == Q_T_A) {
      long *p;
      p = (long *)answers[i].rdata;
      struct sockaddr_in a;
      a.sin_addr.s_addr = (*p); // working without ntohl
      printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
    }

    if (ntohs(answers[i].resource->type) == Q_T_MX) {
      // Canonical name for an alias
      printf("has mail hostname : %s（preference: %d）", answers[i].rdata+2, ntohs(*(unsigned short *)answers[i].rdata));
    }

    if (ntohs(answers[i].resource->type) == Q_T_CNAME) {
      // Canonical name for an alias
      printf("has alias name : %s", answers[i].rdata);
    }

    printf("\n");
  }

  // print authorities
  ResRecord *auth = packet->Authority_RRs;
  printf("\nAuthoritive Records : %d \n", ntohs(dns_header->authorityCount));
  for (int i = 0; i < ntohs(dns_header->authorityCount); i++) {

    printf("  Name : %s ", auth[i].name);
    if (ntohs(auth[i].resource->type) == 2) {
      printf("has nameserver : %s", auth[i].rdata);
    }
    printf("\n");
  }

  // print additional resource records
  ResRecord *addit = packet->Additional_RRs;
  printf("\nAdditional Records : %d \n", ntohs(dns_header->additionalCount));
  for (int i = 0; i < ntohs(dns_header->additionalCount); i++) {
    printf("  Name : %s ", addit[i].name);
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
      // 出现过的name采用压缩指针的方式
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
