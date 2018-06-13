#include "DNSPacket.h"

int addResRecord(unsigned char *reader, ResRecord *resRecord);
int addResRecord_MX(unsigned char *reader, const char *name, unsigned short preference, const char *exchange);
int addResRecord_A(unsigned char *reader, const char *name, const char *address);
int addResRecord_CNAME(unsigned char *reader, const char *name,  const char *cname);
