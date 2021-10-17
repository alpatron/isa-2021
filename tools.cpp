#include "tools.hpp"
#include <stdint.h>
#include <cstddef>
#include <arpa/inet.h>
#include <cstring>
#include <netinet/ip_icmp.h>
#include <stdexcept>

bool compareIPv4Sender(void* IP_packet,size_t size,Address* address){
    if (size < sizeof(iphdr)){
        throw std::runtime_error("IP packet cannot possibly be this small. (You shouldn't see this error.)");
    }
    return ((iphdr*)IP_packet)->saddr == (uint32_t)address->address->sa_data;
}

size_t calculateIPv4HeaderOffset(void* IP_packet,size_t size){
    if (size < sizeof(iphdr)){
        throw std::runtime_error("IP packet cannot possibly be this small. (You shouldn't see this error.)");
    }
    return ((iphdr*)IP_packet)->ihl;
}

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

size_t buildEchoMessage(bool reply, uint16_t identifier, uint16_t sequence, const void* payload, size_t payloadLenght, uint8_t* out){
    ((icmphdr*)out)->type = reply ? ICMP_ECHOREPLY : ICMP_ECHO;
    ((icmphdr*)out)->code = 0;
    ((icmphdr*)out)->un.echo.id = htons(identifier);
    ((icmphdr*)out)->un.echo.sequence = htons(sequence);
    memcpy(out+ICMP_ECHO_HEADER_SIZE,payload,payloadLenght);
    ((icmphdr*)out)->checksum = htons(calculateChecksum((uint8_t*)out,payloadLenght+8));
    return payloadLenght + ICMP_ECHO_HEADER_SIZE;
}

bool isMyReplyICMP_Packet(uint8_t* original_ICMP_packet,uint8_t* receivedPacket,size_t originalSize, size_t receivedSize){
    if (originalSize != receivedSize){
        return false;
    }
    if (((icmphdr*)receivedPacket)->type != ICMP_ECHOREPLY || ((icmphdr*)receivedPacket)->code != 0){
        return false;
    }
    if (((icmphdr*)receivedPacket)->un.echo.id != ((icmphdr*)original_ICMP_packet)->un.echo.id ||
        ((icmphdr*)receivedPacket)->un.echo.sequence != ((icmphdr*)original_ICMP_packet)->un.echo.sequence){
        return false;
    }
    return memcmp(original_ICMP_packet+ICMP_ECHO_HEADER_SIZE,receivedPacket+ICMP_ECHO_HEADER_SIZE,originalSize) == 0;
}