#include "DNSPacket.h"
#include <glib-2.0/glib.h>
#include <stdio.h>
#include <stdlib.h>

GHashTable *readResRecords(const char *prefix) {
  FILE *fp;
  char filename[256] = "data/";
  strcat(filename, prefix);
  strcat(filename, ".txt");
  fp = fopen(filename, "r");
  if (fp == NULL) {
    printf("打开资源记录文件失败");
    exit(1);
  }
  GHashTable *RRTables = g_hash_table_new(g_str_hash, g_str_equal);
  char *rr_types[5] = {"A", "CNAME", "MX", "NS", "PTR"};
  for (int i = 0; i < 5; i++) {
    g_hash_table_insert(RRTables, g_strdup(rr_types[i]),
                        g_hash_table_new(g_str_hash, g_str_equal));
  }
  ResRecord *rr = (ResRecord *)malloc(sizeof(ResRecord));
  rr->name = (unsigned char *)malloc(256);
  rr->rdata = (unsigned char *)malloc(256);
  rr->resource = (R_Data *)malloc(sizeof(R_Data));
  char _class[8], _type[8];
  GHashTable *_table;
  while (fscanf(fp, "%s %d %s %s %s", rr->name, &rr->resource->ttl, _class,
                _type, rr->rdata) != EOF) {
    _table = (GHashTable *)g_hash_table_lookup(RRTables, _type);
    g_hash_table_insert(_table, rr->name, rr);
    rr = (ResRecord *)malloc(sizeof(ResRecord));
    rr->name = (unsigned char *)malloc(256);
    rr->rdata = (unsigned char *)malloc(256);
    rr->resource = (R_Data *)malloc(sizeof(R_Data));
  }
  return RRTables;
}
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
    g_hash_table_insert(table, rr->name, rr);
    rr = (ResRecord *)malloc(sizeof(ResRecord));
    rr->name = (unsigned char *)malloc(256);
    rr->rdata = (unsigned char *)malloc(256);
    rr->resource = (R_Data *)malloc(sizeof(R_Data));
  }
  return table;
}
int run(const char *prefix, char *host) {

  GHashTable *RRTables, *cacheTable, *_table;
  RRTables = readResRecords(prefix);
  cacheTable = readCacheFile(prefix);
  _table = (GHashTable *)g_hash_table_lookup(RRTables, "A");
  printf("%d\n", g_hash_table_size(_table));
  return 0;
}
