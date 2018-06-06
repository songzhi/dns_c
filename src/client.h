#include "DNSPacket.h"
void sendPacketAndGetResult(unsigned char *buf, int data_len);
int setDNSPacket(unsigned char *buf, Query *questions, int ques_count);
