#include <stdint.h>
#include <cstddef>

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