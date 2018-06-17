#include "server.h"

int IS_RECURSIVE = 0;
GHashTable *CACHE_TABLES;
FILE *CACHE_FP;
char *RR_TYPES[32];

int addResRecord(unsigned char *reader, ResRecord *rr) {
  unsigned char *name = (unsigned char *) malloc(256);
  strcpy(name, rr->name);
  switch (rr->resource->type) {
    case Q_T_A:
      return addResRecord_A(reader, (const char *) name, rr->resource->ttl, (const char *) rr->rdata);
    case Q_T_CNAME:
      return addResRecord_CNAME(reader, (const char *) name, rr->resource->ttl, (const char *) rr->rdata);
    case Q_T_MX:
      return addResRecord_MX(reader, (const char *) name, rr->resource->ttl, 5, (const char *) rr->rdata);
    case Q_T_NS:
      return addResRecord_NS(reader, (const char *) name, rr->resource->ttl, (const char *) rr->rdata);
    case Q_T_PTR:
      return addResRecord_PTR(reader, (const char *) name, rr->resource->ttl, (const char *) rr->rdata);
  }
}

int searchFromCache(unsigned char *buf, DNS_Packet *packet, GHashTable *tables) {
  GList *answers = NULL, *additionals = NULL;

  Query *query = packet->Questions;
  const char *rr_type = RR_TYPES[ntohs(query->question->qtype)];
  if (g_hash_table_contains(tables, rr_type)) {
    GHashTable *table = (GHashTable *) g_hash_table_lookup(tables, rr_type);
    if (g_hash_table_contains(table, query->name)) {
      answers = (GList *) g_hash_table_lookup(table, query->name);
      if (query->question->qtype == Q_T_MX) {
        table = (GHashTable *) g_hash_table_lookup(tables, RR_TYPES[Q_T_MX]);
        additionals = (GList *) g_hash_table_lookup(table, ((ResRecord *) answers->data)->rdata);
      }
    }
  }
  if (answers == NULL) {
    return 0;
  }
  DNS_Header *header = (DNS_Header *) buf;
  int data_len = sizeof(DNS_Header);
  unsigned char *reader = buf + data_len;
  for (int i = 0; i < ntohs(packet->Header->queryCount); i++) {
    data_len += addQuery(reader, query + i);
    reader = buf + data_len;
  }
  int ansCount = 0, addiCount = 0;
  for (GList *node = answers; node != NULL;
       node = g_list_next(node), ansCount++) {
    ResRecord *rr = (ResRecord *) node->data;
    data_len += addResRecord(reader, rr);
    reader = buf + data_len;
  }
  for (GList *node = additionals; node != NULL;
       node = g_list_next(node), addiCount++) {
    ResRecord *rr = (ResRecord *) node->data;
    data_len += addResRecord(reader, rr);
    reader = buf + data_len;
  }
  setDNSHeader(header, ansCount, 0, 1, addiCount);
  return data_len;
}

int resolve(unsigned char *buf, DNS_Packet *packet) {
  unsigned char tldbuf[65536];
  memcpy(tldbuf, buf, 65536);
  int data_len;
  if ((data_len= searchFromCache(buf, packet, CACHE_TABLES)) !=0) {
    printf("从缓存中查找成功并返回\n");
    return data_len;
  }
  data_len = packet->data_len;
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
    DNS_Header *header = (DNS_Header *) tldbuf;
    header->rd = IS_RECURSIVE;
    sendto(sock, tldbuf, data_len, 0, (struct sockaddr *) &root_addr_udp,
           sin_size);
    printf("Done\nReceiving from %s...", inet_ntoa(root_addr_udp.sin_addr));
    n = recvfrom(sock, (char *) tldbuf, 65536, 0,
                 (struct sockaddr *) &root_addr_udp, &sin_size);
    printf("Done\n");

    if (IS_RECURSIVE) {
      memcpy(buf, tldbuf, n);
      DNS_Header *dnsHeader = (DNS_Header *) buf;
      dnsHeader->rd = 1;
      data_len = n;
      break;
    } else {
      readDNSPacket(tldbuf, &tld_packet);
      printPacket(&tld_packet);
      if (tld_packet.Header->rcode == 0 &&
          tld_packet.Header->answerCount == 0) {
        printf("正向别的服务器查询\n");
        root_addr_udp.sin_addr.s_addr = *(long *) tld_packet.Additional_RRs[0].rdata;
      } else {
        memcpy(buf, tldbuf, n);
        data_len = n;
        break;
      }
    }
    if (tld_packet.Header->rcode == 0 &&
        tld_packet.Header->answerCount != 0) { // 缓存成功的查询
      for (int i = 0; i < ntohs(tld_packet.Header->answerCount); i++) {
        ResRecord *rr = tld_packet.Answer_RRs + i;
        char *rdata;
        if (ntohs(rr->resource->type) == Q_T_A) {
          long *p = (long *) rr->rdata;
          struct sockaddr_in a;
          a.sin_addr.s_addr = (*p);
          rdata = inet_ntoa(a.sin_addr);
        } else {
          rdata = rr->rdata;
        }
        fprintf(CACHE_FP, "%s %d %s %s %s\n", rr->name, ntohl(rr->resource->ttl), "IN",
                RR_TYPES[ntohs(rr->resource->type)], rdata);
        fflush(CACHE_FP);
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
  scanf("%d", &IS_RECURSIVE);
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


  if (bind(serverSock, (struct sockaddr *) &local_addr,
           sizeof(struct sockaddr)) == -1) {
    perror("server bind failed:");
  }
  if (listen(serverSock, 10) == -1) {
    perror("listhen failed:");
  }

  printf("Listhening:\n");

  socklen_t sin_size = sizeof(struct sockaddr_in);
  while (1) {
    clientSock = accept(serverSock, (struct sockaddr *) &remote_addr, &sin_size);
    int n = recv(clientSock, buf, 65536, 0);
    DNS_Packet packet;
    readDNSPacket(buf + 2, &packet);
    printf("收到");
    printPacket(&packet);
    int data_len = resolve(buf + 2, &packet);
    *(unsigned short *) buf = htons(data_len);
    send(clientSock, buf, data_len + 2, 0);
  }
}
