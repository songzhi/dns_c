#include "server.h"


void setDNSHeader(DNS_Header *header, uint16_t answerCount, uint16_t authCount, uint16_t recursionDesired,
                  uint16_t addCount) {
  header->qr = 1;     // This is a response
  header->opcode = 0; // This is a standard query
  header->aa = 1;     // Not Authoritative
  header->rd = htons(recursionDesired);
  header->answerCount = htons(answerCount);
  header->authorityCount = htons(authCount);
  header->additionalCount = htons(addCount);
  if (answerCount + authCount+addCount ==0) {
    header->rcode = 3;
  } else {
    header->rcode = 0;
  }
}

int addQuery(unsigned char *reader, Query *query) {
  unsigned char *qname = reader;
  changeToDnsNameFormat(qname, query->name);
  int qname_len = strlen((const char *)qname) + 1;
  Question *qinfo = (Question *)&reader[qname_len];
  qinfo->qtype = query->question->qtype;
  qinfo->qclass = query->question->qclass;
  return qname_len + (int)sizeof(Question);
}

int _addResRecord(unsigned char *reader, ResRecord *resRecord) {
  unsigned char *name = reader;
  changeToDnsNameFormat(name, resRecord->name);
  int name_len = strlen((const char *)name) + 1;
  R_Data *r_data = (R_Data *)&reader[name_len];
  r_data->ttl = htonl(resRecord->resource->ttl);
  r_data->type = htons(resRecord->resource->type);
  r_data->data_len = htons(resRecord->resource->data_len);
  r_data->_class = htons(resRecord->resource->_class);
  reader += name_len + sizeof(R_Data);
  memcpy(reader, resRecord->rdata, resRecord->resource->data_len);
  return name_len + sizeof(R_Data) + resRecord->resource->data_len;
}

int addResRecord_A(unsigned char *reader, const char *name, int ttl,
                   const char *address) {
  ResRecord res_record;
  res_record.name = (unsigned char *)malloc(256);
  strcpy((char *)res_record.name, (char *)name);
  res_record.resource = (R_Data *)malloc(sizeof(R_Data));
  res_record.resource->data_len = 4;
  res_record.resource->ttl = ttl;
  res_record.resource->type = Q_T_A;
  res_record.resource->_class = T_IN;
  res_record.rdata = (unsigned char *)malloc(4);
  long *p = (long *)res_record.rdata;
  *p = inet_addr(address);
  return _addResRecord(reader, &res_record);
}

int addResRecord_CNAME(unsigned char *reader, const char *name, int ttl,
                       const char *cname) {
  ResRecord res_record;
  res_record.name = (unsigned char *)malloc(256);
  strcpy((char *)res_record.name, (char *)name);
  res_record.resource = (R_Data *)malloc(sizeof(R_Data));
  res_record.resource->data_len = strlen((char *)cname) + 2;
  res_record.resource->ttl = ttl;
  res_record.resource->type = Q_T_CNAME;
  res_record.resource->_class = T_IN;
  res_record.rdata =
      (unsigned char *)malloc(res_record.resource->data_len + 10);
  changeToDnsNameFormat(res_record.rdata, (unsigned char *)cname);
  return _addResRecord(reader, &res_record);
}

int addResRecord_NS(unsigned char *reader, const char *name, int ttl,
                    const char *cname) {
  ResRecord res_record;
  res_record.name = (unsigned char *)malloc(256);
  strcpy((char *)res_record.name, (char *)name);
  res_record.resource = (R_Data *)malloc(sizeof(R_Data));
  res_record.resource->data_len = strlen((char *)cname) + 2;
  res_record.resource->ttl = ttl;
  res_record.resource->type = Q_T_NS;
  res_record.resource->_class = T_IN;
  res_record.rdata =
      (unsigned char *)malloc(res_record.resource->data_len + 10);
  changeToDnsNameFormat(res_record.rdata, (unsigned char *)cname);
  return _addResRecord(reader, &res_record);
}

int addResRecord_MX(unsigned char *reader, const char *name, int ttl,
                    unsigned short preference, const char *exchange) {
  ResRecord res_record;
  res_record.name = (unsigned char *)malloc(256);
  strcpy((char *)res_record.name, (char *)name);
  res_record.resource = (R_Data *)malloc(sizeof(R_Data));
  res_record.resource->data_len = strlen((char *)exchange) + 2 + 2;
  res_record.resource->ttl = ttl;
  res_record.resource->type = Q_T_MX;
  res_record.resource->_class = T_IN;
  res_record.rdata =
      (unsigned char *)malloc(res_record.resource->data_len + 10);
  unsigned short *p = (unsigned short *)res_record.rdata;
  *p = htons(preference);
  changeToDnsNameFormat(res_record.rdata + 2, (unsigned char *)exchange);
  return _addResRecord(reader, &res_record);
}

GHashTable *readResRecords(const char *filename) {
  FILE *fp;
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
    GList *list = g_hash_table_contains(_table, rr->name)
                      ? (GList *)g_hash_table_lookup(_table, rr->name)
                      : NULL;
    list = g_list_prepend(list, rr);
    j
    g_hash_table_insert(_table, rr->name, list);

    rr = (ResRecord *)malloc(sizeof(ResRecord));
    rr->name = (unsigned char *)malloc(256);
    rr->rdata = (unsigned char *)malloc(256);
    rr->resource = (R_Data *)malloc(sizeof(R_Data));
  }
  return RRTables;
}