#include "DNSPacket.h"
#include "server.h"
#include <glib-2.0/glib.h>
#include <stdio.h>
#include <stdlib.h>

char *RR_TYPES[32];

int addResRecord(unsigned char *reader, ResRecord *rr) {
  switch (rr->resource->type) {
  case Q_T_A:
    return addResRecord_A(reader, (const char *)rr->name, rr->resource->ttl, (const char *)rr->rdata);
    break;
  case Q_T_CNAME:
    return addResRecord_CNAME(reader, (const char *)rr->name, rr->resource->ttl, (const char *)rr->rdata);
    break;
  case Q_T_MX:
    return addResRecord_MX(reader, (const char *)rr->name, rr->resource->ttl, 5, (const char *)rr->rdata);
    break;
  case Q_T_NS:
    return addResRecord_NS(reader, (const char *)rr->name, rr->resource->ttl, (const char *)rr->rdata);
    break;
  }
}

unsigned char *getnshost(const unsigned char *name, const unsigned char *host) {
  unsigned char *r_name = (unsigned char *)g_strreverse(g_strdup((char *)name));
  unsigned char *r_host = (unsigned char *)g_strreverse(g_strdup((char *)host));
  unsigned char *nshost = (unsigned char *)malloc(256);
  int i;
  int host_len = strlen((char *)host);
  for (i = 0; i < host_len; i++) {
    nshost[i] = r_name[i];
  }
  nshost[i++] = '.';
  for (; r_name[i] != '.'; i++) {
    nshost[i] = r_name[i];
  }
  return (unsigned char *)g_strreverse((char *)nshost);
}

int resolve(unsigned char *buf, DNS_Packet *packet, const char *serverHost,
            GHashTable *tables) {
  GList *answers = NULL, *authorities = NULL, *additionals = NULL;

  Query *query = packet->Questions;
  const char *rr_type = RR_TYPES[query->question->qtype];
  if (g_hash_table_contains(tables, rr_type)) {
    GHashTable *table = (GHashTable *)g_hash_table_lookup(tables, rr_type);
    if (g_hash_table_contains(table, query->name)) {
      answers = (GList *)g_hash_table_lookup(table, query->name);
    }
  } else {
    GHashTable *table =
        (GHashTable *)g_hash_table_lookup(tables, RR_TYPES[Q_T_NS]);
    unsigned char *nshost =
        getnshost(query->name, (const unsigned char *)serverHost);
    if (g_hash_table_contains(table, nshost)) {
      authorities = (GList *)g_hash_table_lookup(table, nshost);
      table = (GHashTable *)g_hash_table_lookup(tables, RR_TYPES[Q_T_A]);
      additionals = (GList *)g_hash_table_lookup(
          table, ((ResRecord *)authorities->data)->name);
    }
  }

  DNS_Header *header = (DNS_Header *)buf;
  int data_len = sizeof(DNS_Header);
  unsigned char *reader = buf + data_len;
  int ansCount = 0, authCount = 0, addiCount = 0;
  if (answers != NULL) {
    for (GList *node = answers; node != NULL;
         node = g_list_next(node), ansCount++) {
      ResRecord *rr = (ResRecord *)node->data;
      data_len += addResRecord(reader, rr);
      reader = buf + data_len;
    }
  } else if (authorities != NULL) {
    for (GList *node = authorities; node != NULL;
         node = g_list_next(node), authCount++) {
      ResRecord *rr = (ResRecord *)node->data;
      data_len += addResRecord(reader, rr);
      reader = buf + data_len;
    }
    for (GList *node = additionals; node != NULL;
         node = g_list_next(node), addiCount++) {
      ResRecord *rr = (ResRecord *)node->data;
      data_len += addResRecord(reader, rr);
      reader = buf + data_len;
    }
  }
  setDNSHeader(header, ansCount, authCount, packet->Header->rd, addiCount);
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

void run(const char *prefix, char *host) {
  GHashTable *RRTables, *_table;
  char filename[256] = "data/";
  strcat(filename, prefix);
  strcat(filename, ".txt");
  RRTables = readResRecords(filename);

  initRR_TYPES();

  unsigned char buf[65536];
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in addr_serv;
  addr_serv.sin_family = AF_INET;
  addr_serv.sin_addr.s_addr = inet_addr(host);
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
    printPacket(&packet);
    int data_len = resolve(buf, &packet, prefix, RRTables);
    sendto(s, (char *)buf, data_len, 0, (struct sockaddr *)&dest, (socklen_t)i);
  }
}

int main(void) {
  initRR_TYPES();
  run("root", ROOT_SERVER_HOST);
  return 0;
}
