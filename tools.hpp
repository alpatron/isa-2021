#ifndef TOOLS_H
#define TOOLS_H

#include <stdint.h>
#include <cstddef>
#include "addressResolution.hpp"

#define ICMP_ECHO_HEADER_SIZE 8
#define ORIGINATE_IDENTIFIER "riko"
#define ANSWER_IDENTIFIER "regu"

bool compareIPv4Sender(void* IP_packet,size_t size,Address* address);
size_t calculateIPv4HeaderOffset(void* IP_packet,size_t size);
uint16_t calculateChecksum(const uint8_t* ICMP_message,size_t len);
size_t buildEchoMessage(bool reply, uint16_t identifier, uint16_t sequence, const void* payload, size_t payloadLenght, uint8_t* out);
bool isMyReplyICMP_Packet(uint8_t* original_ICMP_packet,uint8_t* receivedPacket,size_t originalSize, size_t receivedSize);

#endif