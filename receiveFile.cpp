#include "tools.hpp"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdexcept>
#include <cstring>
#include <poll.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <fstream>

#define IPV4_SOCKET_OFFSET 0
#define IPV6_SOCKET_OFFSET 1

bool isMyPacketIPv4(uint8_t* packet,size_t packetSize,uint32_t expectedPacketNumber,uint32_t expectedAddress){
    if(packetSize < sizeof(iphdr)){
        throw std::runtime_error("IP packet cannot possibly be this small. (You shouldn't see this error.)");
    }
    if (expectedPacketNumber != 0){
        if (((iphdr*)packet)->saddr != expectedAddress)
            return false;
    }
    auto offset = calculateIPv4HeaderOffset(packet,packetSize);
    if (packetSize - offset < sizeof(icmphdr)){
        throw std::runtime_error("ICMP packet cannot possibly be this small. (You shouldn't see this error.)");
    }
    if (((icmphdr*)packet+offset)->type != ICMP_ECHO || ((icmphdr*)packet+offset)->code != 0){
        return false;
    }
    if (((icmphdr*)packet+offset)->un.echo.sequence != htons((uint16_t)((expectedPacketNumber & 0xffff))) || ((icmphdr*)packet+offset)->un.echo.id != (uint16_t)((expectedPacketNumber & 0xffff0000) >> 16)){
        return false;
    }
    offset += ICMP_ECHO_HEADER_SIZE;
    if (packetSize - offset < sizeof(ORIGINATE_IDENTIFIER))
        return false;
    return memcmp(packet+offset,ORIGINATE_IDENTIFIER,sizeof(ORIGINATE_IDENTIFIER)-1) == 0; //Terminating binary zero is not included in a packet.
}

void processInitialTransferPacket(uint8_t* packet, size_t packetSize, char* out_filename, size_t maxFilenameLength, uint32_t* out_packetCount,size_t* out_dataOffset){
    auto offset = calculateIPv4HeaderOffset(packet,packetSize) + ICMP_ECHO_HEADER_SIZE + sizeof(ORIGINATE_IDENTIFIER) - 1;
    *out_packetCount = ntohl(*((uint32_t*)(packet+offset)));
    offset += sizeof(uint32_t);
    auto fileNameLenght = strnlen((char*)(packet+offset),packetSize - offset);
    if (fileNameLenght == packetSize - offset){
        throw std::runtime_error("Malformed initial packet!");
    }
    strcpy(out_filename,(char*)(packet+offset));
    offset += fileNameLenght + 1;
    *out_dataOffset = offset;
}

void receiveFile(int socket,bool IPv6){
    uint8_t receiveBuffer[1500];
    auto packetSize = recv(socket,receiveBuffer,sizeof(receiveBuffer),NULL);
    if (!isMyPacketIPv4(receiveBuffer,packetSize,0,NULL))
        return;
    
    uint32_t packetCount;
    char filename[1500];
    size_t initialDataOffset;
    try{
        processInitialTransferPacket(receiveBuffer,packetSize,filename,1500,&packetCount,&initialDataOffset);
    } catch (std::runtime_error& e){
        return;
    }

    auto outputFile = std::ofstream(filename,std::ofstream::binary);
}

[[noreturn]] void receiveFiles(){
    auto IPv4_socket = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    if (IPv4_socket == -1){
        if (errno == EACCES){
            throw std::runtime_error("This programs needs to be run with super-user privileges.");
        } else {
            throw std::runtime_error(strerror(errno));
        }
    }
    auto IPv6_socket = socket(AF_INET6,SOCK_RAW,IPPROTO_ICMPV6);
    if (IPv6_socket == -1){
        if (errno == EACCES){
            throw std::runtime_error("This programs needs to be run with super-user privileges.");
        } else {
            throw std::runtime_error(strerror(errno));
        }
    }
    pollfd polledSockets[] = {
        {
            .fd = IPv4_socket,
            .events = POLLIN
        },
        {
            .fd = IPv6_socket,
            .events = POLLIN
        }
    };

    while(true){
        auto pollResult = poll(polledSockets,std::size(polledSockets),-1);
        if (pollResult == -1){
            throw std::runtime_error(strerror(errno));
        }
        if(polledSockets[IPV4_SOCKET_OFFSET].events & POLLIN){
            receiveFile(IPv4_socket,false);
        } else if (polledSockets[IPV4_SOCKET_OFFSET].events & POLLIN){
            receiveFile(IPv6_socket,true);
        } else if (polledSockets[IPV4_SOCKET_OFFSET].revents & POLLERR || polledSockets[IPV6_SOCKET_OFFSET].revents & POLLERR) {
            break;
        } else {
            throw std::runtime_error("You should never see this error. If you see this line, something is horribly broken.");
        }
    }
}