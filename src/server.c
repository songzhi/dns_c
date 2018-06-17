#include "server.h"


void setDNSHeader(DNS_Header *header, uint16_t answerCount, uint16_t authCount, uint16_t recursionDesired,
                  uint16_t addCount) {
  // 因为这个函数只在服务器端使用，所以有些字段不用设置
  header->qr = 1;     // This is a response
  header->opcode = 0; // This is a standard query
  header->aa = 1;     // Not Authoritative
  header->rd = recursionDesired;
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
  qinfo->qclass = htons(T_IN);
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
  res_record.resource->data_len = strlen((char *)cname) + 2; // 转换格式之后长度加二
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
  res_record.resource->data_len = strlen((char *)cname) + 2; // 转换格式之后长度加二
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
  res_record.resource->data_len = strlen((char *)exchange) + 2 + 2; // exchange转换格式之后长度加二，另一个2是preference
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

int addResRecord_PTR(unsigned char *reader, const char *name, int ttl,
                       const char *cname) {
  ResRecord res_record;
  res_record.name = (unsigned char *)malloc(256);
  strcpy((char *)res_record.name, (char *)name);
  res_record.resource = (R_Data *)malloc(sizeof(R_Data));
  res_record.resource->data_len = strlen((char *)cname) + 2; // 转换格式之后长度加二
  res_record.resource->ttl = ttl;
  res_record.resource->type = Q_T_PTR;
  res_record.resource->_class = T_IN;
  res_record.rdata =
          (unsigned char *)malloc(res_record.resource->data_len + 10);
  changeToDnsNameFormat(res_record.rdata, (unsigned char *)cname);
  return _addResRecord(reader, &res_record);
}

GHashTable *readResRecords(const char *filename) {
  // 从文件里读取资源记录，保存到一张hash表里。
  // key是几种资源的类型，value是hash表，其维护对应类型的所有资源记录
  FILE *fp;
  GHashTable *RRTables = g_hash_table_new(g_str_hash, g_str_equal);
  fp = fopen(filename, "r");
  if (fp == NULL) {
    printf("资源记录文件不存在\n");
    return RRTables;
  }
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
    if (strcmp(_type, "MX") == 0) {
      rr->resource->type = Q_T_MX;
    } else if (strcmp(_type, "A") == 0) {
      rr->resource->type = Q_T_A;
    } else if (strcmp(_type, "CNAME") == 0) {
      rr->resource->type = Q_T_CNAME;
    } else if (strcmp(_type, "PTR") == 0) {
      rr->resource->type = Q_T_PTR;
    }else if (strcmp(_type, "NS") == 0) {
      rr->resource->type = Q_T_NS;
    }
    g_hash_table_insert(_table, rr->name, list);

    rr = (ResRecord *)malloc(sizeof(ResRecord));
    rr->name = (unsigned char *)malloc(256);
    rr->rdata = (unsigned char *)malloc(256);
    rr->resource = (R_Data *)malloc(sizeof(R_Data));
  }
  return RRTables;
}

