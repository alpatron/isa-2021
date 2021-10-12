#include <stdint.h>
#include <cstddef>
#include <arpa/inet.h>
#include <cstring>

#define ICMP_ECHO_TYPE_OFFSET 0
#define ICMP_ECHO_CODE_OFFSET 1
#define ICMP_ECHO_CHECKSUM_OFFSET 2
#define ICMP_ECHO_IDENTIFIER_OFFSET 4
#define ICMP_ECHO_SEQUENCE_OFFSET 6
#define ICMP_ECHO_PAYLOAD_OFFSET 8

uint16_t calculateChecksum(const uint8_t* ICMP_message,size_t len){
    uint32_t sum = 0;
    sum += *((uint16_t*)ICMP_message);
    ICMP_message += 4;
    len -= 4;
    for(;len > 1;len-=2){
        sum += *(uint16_t*)(ICMP_message++);
    }
    if(len>0){
        sum += *ICMP_message;
    }
    return ~(uint16_t)((sum & 0xffff) + (sum >> 16));
}

void buildEchoMessage(bool reply, uint16_t identifier, uint16_t sequence, const void* payload, size_t payloadLenght, uint8_t* out){
    *((uint8_t*)(out+ICMP_ECHO_TYPE_OFFSET)) = reply ? 0 : 8;
    *((uint8_t*)(out+ICMP_ECHO_CODE_OFFSET)) = 0;
    *((uint16_t*)(out+ICMP_ECHO_IDENTIFIER_OFFSET)) = htons(identifier);
    *((uint16_t*)(out+ICMP_ECHO_SEQUENCE_OFFSET)) = htons(sequence);
    memcpy(out+ICMP_ECHO_PAYLOAD_OFFSET,payload,payloadLenght);
    *((uint16_t*)(out+ICMP_ECHO_CHECKSUM_OFFSET)) = htons(calculateChecksum((uint8_t*)out,payloadLenght+8));
}