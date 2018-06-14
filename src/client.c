#include "client.h"

void setDNSHeader(DNS_Header *header, uint16_t id, uint16_t queryCount) {
  header->id = htons(id);
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
  header->answerCount = 0;
  header->authorityCount = 0;
  header->additionalCount = 0;
}

int addQuery(unsigned char *reader, Query *query) {
  unsigned char *qname = reader;
  changeToDnsNameFormat(qname, query->name);
  int qname_len = strlen((const char *)qname) + 1;
  Question *qinfo = (Question *)&reader[qname_len];
  qinfo->qtype = htons(query->question->qtype);
  qinfo->qclass = htons(query->question->qclass); // internet
  return qname_len + (int)sizeof(Question);
}

int setDNSPacket(unsigned char *buf, Query *questions, int ques_count) {
  DNS_Header *dns_header = (DNS_Header *)buf+2;
  setDNSHeader(dns_header,getpid() ,ques_count);
  int ques_len = 0;
  for (int i = 0; i < ques_count; i++) {
    ques_len += addQuery(&buf[sizeof(DNS_Header) + ques_len], questions + i);
  }
  int data_len = (int)sizeof(DNS_Header) + ques_len;
  *(unsigned short *)buf = htons(data_len);
  return data_len;
}

void sendPacketAndGetResult(unsigned char *buf, int data_len) {
  struct sockaddr_in dest;
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  dest.sin_family = AF_INET;
  dest.sin_port = htons(53);
  dest.sin_addr.s_addr = inet_addr("127.0.0.155");
  printf("\nSending Packet...");
  connect(sock, (struct sockaddr*)&dest, sizeof(dest));
  if (send(sock, (char *)buf, data_len, 0) < 0) {
    perror("sendto failed");
  }
  printf("Done");
  int i = sizeof dest;
  printf("\nReceiving answer...");
  if (recv(sock, (char *)buf, 65536, 0) < 0) {
    perror("recvfrom failed");
  }
  printf("Done\n");
}

int main(void) {
  printf("问题数量:");
  int ques_count;
  scanf("%d", &ques_count);
  Query *questions = (Query *)malloc(sizeof(Query) * ques_count);
  for (int i = 0; i < ques_count; i++) {
    questions[i].name = (unsigned char *)malloc(sizeof(unsigned char) * 256);
    questions[i].question = (Question *)malloc(sizeof(Question));
    printf("域名:");
    scanf("%s", questions[i].name);
    printf("类型(A:1\\MS:15\\CNAME:5):");
    scanf("%hu", &(questions[i].question->qtype));
    questions[i].question->qclass = 1;
  }
  unsigned char buf[65536];
  int data_len = setDNSPacket(buf, questions, ques_count);
  sendPacketAndGetResult(buf, data_len);
  DNS_Packet packet;
  readDNSPacket(buf+2, &packet);
  printPacket(&packet);
  return 0;
}
