#include "server.h"
#include <glib-2.0/glib.h>

int IS_RECURSIVE = 0;

GHashTable *readCacheFile(const char *prefix) {
  GHashTable *table = g_hash_table_new(g_str_hash, g_str_equal);
  FILE *fp;
  char filename[256] = "data/";
  strcat(filename, prefix);
  strcat(filename, ".cache");
  if ((fp = fopen(filename, "r")) == NULL) {
    return table;
  }
  ResRecord *rr = (ResRecord *)malloc(sizeof(ResRecord));
  rr->name = (unsigned char *)malloc(256);
  rr->rdata = (unsigned char *)malloc(256);
  rr->resource = (R_Data *)malloc(sizeof(R_Data));
  char _class[8], _type[8];
  while (fscanf(fp, "%s %d %s %s %s", rr->name, &rr->resource->ttl, _class,
                _type, rr->rdata) != EOF) {
    GList *list = g_hash_table_contains(table, rr->name)
                      ? (GList *)g_hash_table_lookup(table, rr->name)
                      : NULL;
    list = g_list_prepend(list, rr);
    g_hash_table_insert(table, rr->name, list);
    rr = (ResRecord *)malloc(sizeof(ResRecord));
    rr->name = (unsigned char *)malloc(256);
    rr->rdata = (unsigned char *)malloc(256);
    rr->resource = (R_Data *)malloc(sizeof(R_Data));
  }
  return table;
}

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
    printf("sending to root...");
    DNS_Header *header = (DNS_Header *)tldbuf;
    header->rd = htons(IS_RECURSIVE);
    sendto(sock, tldbuf, data_len, 0, (struct sockaddr *)&root_addr_udp,
           sin_size);
    printf("Done\nreceiving from root...");
    n = recvfrom(sock, (char *)tldbuf, 65536, 0,
                 (struct sockaddr *)&root_addr_udp, &sin_size);
    printf("Done\n");

    if (IS_RECURSIVE) {
      memcpy(buf, tldbuf, n);
      data_len = n;
    } else {
      readDNSPacket(tldbuf, &tld_packet);
      printPacket(&tld_packet);
      if (tld_packet.Header->rcode == 0 &&
          tld_packet.Header->answerCount == 0) {
        root_addr_udp.sin_addr.s_addr =
            inet_addr((const char *)tld_packet.Additional_RRs[0].rdata);
      } else {
        memcpy(buf, tldbuf, n);
        data_len = n;
        break;
      }
    }
  }
  return data_len;
}

int main(void) {
  unsigned char buf[65536];
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
    printPacket(&packet);
    int data_len = resolve(buf+2, &packet);
    *(unsigned short *)buf = htons(data_len);
    send(clientSock, buf, data_len, 0);
  }
}
