#ifndef ICMP_MESSAGE_H
#define ICMP_MESSAGE_H

#include <stdint.h>
#include <cstddef>

const size_t ICMP_ECHO_HEADER_SIZE = 8;

uint16_t calculateChecksum(const uint8_t* ICMP_message,size_t len);
size_t buildEchoMessage(bool reply, uint16_t identifier, uint16_t sequence, const void* payload, size_t payloadLenght, uint8_t* out);
bool isMyReplyICMP_Packet(uint8_t* original_ICMP_packet,uint8_t* receivedPacket,size_t originalSize, size_t receivedSize);

#endif