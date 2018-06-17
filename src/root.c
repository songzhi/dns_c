#include "DNSPacket.h"
#include "server.h"

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

unsigned char *getnshost(const unsigned char *name, const unsigned char *host) {
  unsigned char *r_name = (unsigned char *) g_strreverse(g_strdup((char *) name));
  unsigned char *nshost = (unsigned char *) malloc(256);
  int i;
  int host_len = strlen((char *) host);
  for (i = 0; i < host_len; i++) {
    nshost[i] = r_name[i];
  }
  if (host_len) {
    nshost[i++] = '.';
  }
  for (; r_name[i] != '.'; i++) {
    nshost[i] = r_name[i];
  }
  return (unsigned char *) g_strreverse((char *) nshost);
}

void launchOtherServerFunc(gpointer key, gpointer value, gpointer user_data) {
  GHashTable *a_table = (GHashTable *) user_data;
  ResRecord *rr = (ResRecord *) (((GList *) value)->data);
  GList *hosts = (GList *) g_hash_table_lookup(a_table, rr->rdata);
  char *host = (char *) ((ResRecord *) hosts->data)->rdata;
  char path[256] = "";// /home/lsongzhi/projects/dns/cmake-build-debug/bin/bin/root
  strcat(path, g_get_current_dir());
  strcat(path, "/root");
  if (fork() == 0) {
    execl(path, key, host, NULL);
    perror("子进程创建失败");
  } else {
    printf("Launch Server: Host:%s Port:%s \n", key, host);
  }

}

void launchOtherServers(GHashTable *tables) {
  if (g_hash_table_contains(tables, RR_TYPES[Q_T_NS])) {
    GHashTable *ns_table = (GHashTable *) g_hash_table_lookup(tables, RR_TYPES[Q_T_NS]);
    GHashTable *a_table = (GHashTable *) g_hash_table_lookup(tables, RR_TYPES[Q_T_A]);
    g_hash_table_foreach(ns_table, launchOtherServerFunc, a_table);
  }
}

int resolve(unsigned char *buf, DNS_Packet *packet, const char *serverHost,
            GHashTable *tables) {
  GList *answers = NULL, *authorities = NULL, *additionals = NULL;

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
    GHashTable *table =
            (GHashTable *) g_hash_table_lookup(tables, RR_TYPES[Q_T_NS]);
    unsigned char *nshost =
            getnshost(query->name, (const unsigned char *) serverHost);
    if (g_hash_table_contains(table, nshost)) {
      authorities = (GList *) g_hash_table_lookup(table, nshost);
      table = (GHashTable *) g_hash_table_lookup(tables, RR_TYPES[Q_T_A]);
      additionals = (GList *) g_hash_table_lookup(
              table, ((ResRecord *) authorities->data)->rdata);
    }
  }

  DNS_Header *header = (DNS_Header *) buf;
  int data_len = sizeof(DNS_Header);
  unsigned char *reader = buf + data_len;
  for (int i = 0; i < ntohs(packet->Header->queryCount); i++) {
    data_len += addQuery(reader, query + i);
    reader = buf + data_len;
  }
  int ansCount = 0, authCount = 0, addiCount = 0;
  if (answers != NULL) {
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
  } else if (authorities != NULL) {
    if (ntohs(packet->Header->rd)) { // 递归查询
      struct sockaddr_in dest_addr;
      int sock = socket(AF_INET, SOCK_DGRAM, 0);
      dest_addr.sin_family = AF_INET;
      ResRecord *rr = (ResRecord *)additionals->data;
      dest_addr.sin_addr.s_addr = inet_addr(rr->rdata);
      dest_addr.sin_port = htons(SERVER_PORT);
      socklen_t sin_size = sizeof(struct sockaddr_in);
      sendto(sock, buf, packet->data_len, 0, (struct sockaddr *) &dest_addr,
             sin_size);
      data_len = recvfrom(sock, (char *) buf, 65536, 0,
                          (struct sockaddr *) &dest_addr, &sin_size);
      return data_len;
    } else {
      for (GList *node = authorities; node != NULL;
           node = g_list_next(node), authCount++) {
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
    }
  }
  setDNSHeader(header, ansCount, authCount, packet->Header->rd, addiCount);
  return data_len;
}


void run(const char *prefix, char *host) {
  GHashTable *RRTables;
  char filename[256] = "data/";
  strcat(filename, prefix);
  strcat(filename, ".txt");
  RRTables = readResRecords(filename);
  launchOtherServers(RRTables);

  unsigned char buf[65536];
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in addr_serv;
  addr_serv.sin_family = AF_INET;
  addr_serv.sin_addr.s_addr = inet_addr(host);
  addr_serv.sin_port = htons(SERVER_PORT);
  if (bind(s, (struct sockaddr *) &addr_serv, sizeof(addr_serv)) < 0) {
    perror("server bind failed");
  }
  struct sockaddr_in dest;
  int i = sizeof(dest);
  while (1) {
    printf("\nPrefix:%s Host:%s\n", prefix, host);
    int n = recvfrom(s, (char *) buf, 65536, 0, (struct sockaddr *) &dest,
                     (socklen_t *) &i);
    DNS_Packet packet;
    readDNSPacket(buf, &packet);
    printPacket(&packet);
    printf("\n");
    int data_len;
    if (strcmp(prefix, "root") == 0) {
      data_len = resolve(buf, &packet, "", RRTables);
    } else {
      data_len = resolve(buf, &packet, prefix, RRTables);
    }
    sendto(s, (char *) buf, data_len, 0, (struct sockaddr *) &dest, (socklen_t) i);
    readDNSPacket(buf, &packet);
    printPacket(&packet);
    printf("\n");
  }
}

void initRR_TYPES(void) {
  RR_TYPES[Q_T_A] = g_strdup("A");
  RR_TYPES[Q_T_NS] = g_strdup("NS");
  RR_TYPES[Q_T_CNAME] = g_strdup("CNAME");
  RR_TYPES[Q_T_SOA] = g_strdup("SOA");
  RR_TYPES[Q_T_PTR] = g_strdup("PTR");
  RR_TYPES[Q_T_MX] = g_strdup("MX");
}

int main(int argc, char *argv[]) {
  initRR_TYPES();

  if (argc == 1) {
    run("root", ROOT_SERVER_HOST);
  } else if (argc == 2) {
    run(argv[0], argv[1]);
  } else {
    printf("命令行参数不正确");
    return -1;
  }
  return 0;
}
