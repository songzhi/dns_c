#include "server.h"

int addQuery(unsigned char *reader, Query *query) {
  unsigned char *qname = reader;
  changeToDnsNameFormat(qname, query->name);
  int qname_len = strlen((const char *)qname) + 1;
  Question *qinfo = (Question *)&reader[qname_len];
  qinfo->qtype = query->question->qtype;
  qinfo->qclass = query->question->qclass;
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
  r_data->_class = htons(resRecord->resource->_class);
  reader += name_len + sizeof(R_Data);
  memcpy(reader, resRecord->rdata, resRecord->resource->data_len);
  return name_len + sizeof(R_Data) + resRecord->resource->data_len;
}

int addResRecord_A(unsigned char *reader, const char *name, const char *address) {
  ResRecord res_record;
  res_record.name = (unsigned char *)malloc(256);
  strcpy((char *)res_record.name, (char *)name);
  res_record.resource = (R_Data *)malloc(sizeof(R_Data));
  res_record.resource->data_len = 4;
  res_record.resource->ttl = TTL;
  res_record.resource->type = Q_T_A;
  res_record.resource->_class = T_IN;
  res_record.rdata = (unsigned char *)malloc(4);
  long *p = (long *)res_record.rdata;
  *p = inet_addr(address);
  return addResRecord(reader, &res_record);
}

int addResRecord_CNAME(unsigned char *reader, const char *name,  const char *cname) {
  ResRecord res_record;
  res_record.name = (unsigned char *)malloc(256);
  strcpy((char *)res_record.name, (char *)name);
  res_record.resource = (R_Data *)malloc(sizeof(R_Data));
  res_record.resource->data_len = strlen((char *)cname) + 2;
  res_record.resource->ttl = TTL;
  res_record.resource->type = Q_T_CNAME;
  res_record.resource->_class = T_IN;
  res_record.rdata = (unsigned char *)malloc(res_record.resource->data_len + 10);
  changeToDnsNameFormat(res_record.rdata, (unsigned char *)cname);
  return addResRecord(reader, &res_record);
}

int addResRecord_NS(unsigned char *reader, const char *name,  const char *cname) {
  ResRecord res_record;
  res_record.name = (unsigned char *)malloc(256);
  strcpy((char *)res_record.name, (char *)name);
  res_record.resource = (R_Data *)malloc(sizeof(R_Data));
  res_record.resource->data_len = strlen((char *)cname) + 2;
  res_record.resource->ttl = TTL;
  res_record.resource->type = Q_T_NS;
  res_record.resource->_class = T_IN;
  res_record.rdata = (unsigned char *)malloc(res_record.resource->data_len + 10);
  changeToDnsNameFormat(res_record.rdata, (unsigned char *)cname);
  return addResRecord(reader, &res_record);
}

int addResRecord_MX(unsigned char *reader, const char *name, unsigned short preference, const char *exchange) {
  ResRecord res_record;
  res_record.name = (unsigned char *)malloc(256);
  strcpy((char *)res_record.name, (char *)name);
  res_record.resource = (R_Data *)malloc(sizeof(R_Data));
  res_record.resource->data_len = strlen((char *)exchange) + 2 + 2;
  res_record.resource->ttl = TTL;
  res_record.resource->type = Q_T_MX;
  res_record.resource->_class = T_IN;
  res_record.rdata = (unsigned char *)malloc(res_record.resource->data_len + 10);
  unsigned short *p = (unsigned short *)res_record.rdata;
  *p = htons(preference);
  changeToDnsNameFormat(res_record.rdata+2, (unsigned char *)exchange);
  return addResRecord(reader, &res_record);
}

int setDNSPacket(unsigned char *buf, DNS_Packet *packet) {
  DNS_Header *dns_header = (DNS_Header *)buf;
  setDNSHeader(dns_header, 1, 3, 0, 0);
  int ques_len = 0;
  for (int i = 0; i < ntohs(packet->Header->queryCount); i++) {
    ques_len +=
        addQuery(&buf[sizeof(DNS_Header) + ques_len], packet->Questions + i);
  }
  
  ques_len += addResRecord_MX(buf + sizeof(DNS_Header) + ques_len, "bupt.edu.cn", 5, "mx1.bupt.edu.cn");
  ques_len += addResRecord_A(buf + sizeof(DNS_Header) + ques_len, "bupt.edu.cn", "127.0.0.1");
  ques_len += addResRecord_CNAME(buf + sizeof(DNS_Header) + ques_len, "bupt.edu.cn", "bupt.cn");
  return (int)sizeof(DNS_Header) + ques_len;
}

int main(void) {
  unsigned char buf[65536];
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in addr_serv;
  addr_serv.sin_family = AF_INET;
  addr_serv.sin_addr.s_addr = inet_addr("127.0.0.155");
  addr_serv.sin_port = htons(53);
  bind(s, (struct sockaddr *)&addr_serv, sizeof(addr_serv));
  struct sockaddr_in dest;
  int i = sizeof(dest);
  printf("listhening\n");
  while (1) {
    int n = recvfrom(s, (char *)buf, 65536, 0, (struct sockaddr *)&dest,
                     (socklen_t *)&i);
    DNS_Packet packet;
    readDNSPacket(buf, &packet);
    int data_len = setDNSPacket(buf, &packet);

    sendto(s, (char *)buf, data_len, 0, (struct sockaddr *)&dest, (socklen_t)i);
    readDNSPacket(buf, &packet);
    printPacket(&packet);
  }
}