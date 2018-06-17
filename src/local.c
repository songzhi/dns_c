#include "server.h"

int IS_RECURSIVE = 0;
GHashTable *CACHE_TABLES;
FILE *CACHE_FP;
char *RR_TYPES[32];

int resolve(unsigned char *buf, DNS_Packet *packet) {
  unsigned char tldbuf[65536];
  memcpy(tldbuf, buf, 65536);
  int data_len = packet->data_len;
  struct sockaddr_in root_addr_udp;
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  root_addr_udp.sin_family = AF_INET;
  root_addr_udp.sin_addr.s_addr = inet_addr(ROOT_SERVER_HOST);
  root_addr_udp.sin_port = htons(SERVER_PORT);
  socklen_t sin_size = sizeof(struct sockaddr_in);
  int n;
  DNS_Packet tld_packet;
  while (1) {
    printf("Sending to %s...", inet_ntoa(root_addr_udp.sin_addr));
    DNS_Header *header = (DNS_Header *)tldbuf;
    header->rd = IS_RECURSIVE;
    sendto(sock, tldbuf, data_len, 0, (struct sockaddr *)&root_addr_udp,
           sin_size);
    printf("Done\nReceiving from %s...", inet_ntoa(root_addr_udp.sin_addr));
    n = recvfrom(sock, (char *)tldbuf, 65536, 0,
                 (struct sockaddr *)&root_addr_udp, &sin_size);
    printf("Done\n");

    if (IS_RECURSIVE) {
      memcpy(buf, tldbuf, n);
      DNS_Header *dnsHeader = (DNS_Header *)buf;
      dnsHeader->rd = 1;
      data_len = n;
      break;
    } else {
      readDNSPacket(tldbuf, &tld_packet);
      printPacket(&tld_packet);
      if (tld_packet.Header->rcode == 0 &&
          tld_packet.Header->answerCount == 0) {
        printf("正向别的服务器查询\n");
        root_addr_udp.sin_addr.s_addr = *(long *)tld_packet.Additional_RRs[0].rdata;
      } else {
        if (tld_packet.Header->rcode == 0) { // 缓存成功的查询
          for (int i=0;i<ntohs(tld_packet.Header->answerCount);i++) {
            ResRecord *rr = tld_packet.Answer_RRs+i;
            char *rdata;
            if (ntohs(rr->resource->type) == Q_T_A) {
              long *p = (long *) rr->rdata;
              struct sockaddr_in a;
              a.sin_addr.s_addr = (*p);
              rdata = inet_ntoa(a.sin_addr);
            }else {
              rdata = rr->rdata;
            }
            fprintf(CACHE_FP, "%s %d %s %s %s\n", rr->name, ntohl(rr->resource->ttl), "IN",
                    RR_TYPES[ntohs(rr->resource->type)], rdata);
            fflush(CACHE_FP);
          }
        }
        memcpy(buf, tldbuf, n);
        data_len = n;
        break;
      }
    }
  }
  return data_len;
}

void initRR_TYPES(void) {
  RR_TYPES[Q_T_A] = g_strdup("A");
  RR_TYPES[Q_T_NS] = g_strdup("NS");
  RR_TYPES[Q_T_CNAME] = g_strdup("CNAME");
  RR_TYPES[Q_T_SOA] = g_strdup("SOA");
  RR_TYPES[Q_T_PTR] = g_strdup("PTR");
  RR_TYPES[Q_T_MX] = g_strdup("MX");
}

int main(void) {
  unsigned char buf[65536];
  printf("选择是否递归查找(1/0):");
  scanf("%d",&IS_RECURSIVE);
  initRR_TYPES();
  CACHE_TABLES = readResRecords("data/local.cache");
  CACHE_FP = fopen("data/local.cache", "a+");
  if (CACHE_FP == NULL) {
    printf("打开缓存文件失败\n");
  }
  int serverSock, clientSock;
  struct sockaddr_in local_addr, remote_addr;
  serverSock = socket(AF_INET, SOCK_STREAM, 0);
  local_addr.sin_family = AF_INET;
  local_addr.sin_addr.s_addr = inet_addr(LOCAL_SERVER_HOST);
  local_addr.sin_port = htons(SERVER_PORT);


  if (bind(serverSock, (struct sockaddr *)&local_addr,
           sizeof(struct sockaddr)) == -1) {
    perror("server bind failed:");
  }
  if (listen(serverSock, 10) == -1) {
    perror("listhen failed:");
  }

  printf("Listhening:\n");

  socklen_t sin_size = sizeof(struct sockaddr_in);
  while (1) {
    clientSock = accept(serverSock, (struct sockaddr *)&remote_addr, &sin_size);
    int n = recv(clientSock, buf, 65536, 0);
    DNS_Packet packet;
    readDNSPacket(buf+2, &packet);
    printf("收到");
    printPacket(&packet);
    int data_len = resolve(buf+2, &packet);
    *(unsigned short *)buf = htons(data_len);
    send(clientSock, buf, data_len+2, 0);
  }
}
