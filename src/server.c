#include "server.h"

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
    recvfrom(s, (char *)buf, 65536, 0, (struct sockaddr *)&dest,
             (socklen_t *)&i);
    DNS_Packet packet;
    readDNSPacket(buf, &packet);
    printPacket(&packet);
  }
}