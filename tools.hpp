#ifndef TOOLS_H
#define TOOLS_H

#include <stdint.h>
#include <cstddef>
#include "addressResolution.hpp"

#define ICMP_ECHO_HEADER_SIZE 8
#define PACKET_IDENTIFIER "regu"

int encrypt(const unsigned char* input, size_t inputSize,uint32_t packetNumber,unsigned char* out);
int decrypt(const unsigned char* input, size_t inputSize,uint32_t packetNumber,unsigned char* out);
bool compareAddress(sockaddr* a, sockaddr* b, bool IPv6);
size_t calculatePacketIPHeaderOffset(void* IP_packet,size_t size, bool IPv6);
size_t calculateIPv4HeaderOffset(void* IP_packet,size_t size);
uint16_t calculateChecksum(const uint8_t* ICMP_message,size_t len);
size_t buildEchoMessage(uint16_t identifier, uint16_t sequence, const void* payload, size_t payloadLength, uint8_t* out,bool IPv6);
bool isMyReplyICMP_Packet(uint8_t* original_ICMP_packet,uint8_t* receivedPacket,size_t originalSize, size_t receivedSize,bool IPv6);

#endif