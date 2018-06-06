#include "server.h"

int setDNSPacket(unsigned char *buf, DNS_Packet *packet) {
  DNS_Header *dns_header = (DNS_Header *)buf;
  setDNSHeader(dns_header, 1, 1, 0, 0);
  int ques_len = 0;
  for (int i = 0; i < ntohs(packet->Header->queryCount); i++) {
    ques_len +=
        addQuery(&buf[sizeof(DNS_Header) + ques_len], packet->Questions + i, 0);
  }
  ResRecord res_record;
  res_record.name = (unsigned char *)malloc(256);
  strcpy((char *)res_record.name, "bupt.edu.cn");
  res_record.resource = (R_Data *)malloc(sizeof(R_Data));
  res_record.resource->data_len = strlen("127.0.0.1");
  res_record.resource->ttl = 300;
  res_record.resource->type = Q_T_A;
  res_record.resource->_class = 1;
  res_record.rdata = (unsigned char *)malloc(255);
  strcpy((char *)res_record.rdata, "127.0.0.1");
  ques_len += addResRecord(buf + sizeof(DNS_Header) + ques_len, &res_record);
  return (int)sizeof(DNS_Header) + ques_len;
}

int main(void) {
  unsigned char buf[65536];
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in addr_serv;
  addr_serv.sin_family = AF_INET;
  addr_serv.sin_addr.s_addr = inet_addr("127.0.0.1");
  addr_serv.sin_port = htons(8888);
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

    sendto(s, (char *)buf, data_len, 0, (struct sockaddr *)&dest,
           (socklen_t)i);
    readDNSPacket(buf, &packet);
    printPacket(&packet);
    // printPacket(&packet);
  }
}