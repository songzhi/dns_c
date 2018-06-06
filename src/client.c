#include "client.h"


int setDNSPacket(unsigned char *buf, Query *questions, int ques_count) {
  DNS_Header *dns_header = (DNS_Header *)buf;
  setDNSHeader(dns_header, ques_count, 0, 0, 0);
  int ques_len = 0;
  for (int i = 0; i < ques_count; i++) {
    ques_len += addQuery(&buf[sizeof(DNS_Header) + ques_len], questions + i);
  }
  return (int)sizeof(DNS_Header) + ques_len;
}

void sendPacketAndGetResult(unsigned char *buf, int data_len) {
  struct sockaddr_in dest;
  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  dest.sin_family = AF_INET;
  dest.sin_port = htons(8888);
  dest.sin_addr.s_addr = inet_addr("127.0.0.1");
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
  readDNSPacket(buf, &packet);
  printPacket(&packet);
  return 0;
}
