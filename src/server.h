#include "DNSPacket.h"
#include <glib-2.0/glib.h>
int _addResRecord(unsigned char *reader, ResRecord *resRecord);
int addResRecord_MX(unsigned char *reader, const char *name, int ttl,
                    unsigned short preference, const char *exchange);
int addResRecord_A(unsigned char *reader, const char *name, int ttl,
                   const char *address);
int addResRecord_CNAME(unsigned char *reader, const char *name, int ttl,
                       const char *cname);
int addQuery(unsigned char *reader, Query *query);
int addResRecord_NS(unsigned char *reader, const char *name, int ttl,
                    const char *cname);
void setDNSHeader(DNS_Header *header, uint16_t answerCount, uint16_t authCount, uint16_t recursionDesired,uint16_t addCount);
GHashTable *readResRecords(const char *filename);
