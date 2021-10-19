#include "receiveFile.hpp"
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
#include <filesystem>
#include <iostream>

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
    if (memcmp(packet+offset,ORIGINATE_IDENTIFIER,sizeof(ORIGINATE_IDENTIFIER)-1) != 0){ //Terminating binary zero is not included in a packet.
        return false;
    }
    if (expectedPacketNumber == 0){ //The initial packet contains packet-count and a filename fields. If the filename field does not contain a null terminator, it's a malformed packet and a buffer over-read would happen.
        offset += sizeof(uint32_t); // Skip the packet-count field.
        auto fileNameLenght = strnlen((char*)(packet+offset),packetSize - offset);
        if (fileNameLenght == packetSize - offset){
            return false;
        }
    }
    return true;
}

void processInitialTransferPacket(uint8_t* packet, size_t packetSize, char* out_filename, size_t maxFilenameLength, uint32_t* out_packetCount,size_t* out_dataOffset,uint32_t* out_address){
    *out_address = ((iphdr*)packet)->saddr;
    auto offset = calculateIPv4HeaderOffset(packet,packetSize) + ICMP_ECHO_HEADER_SIZE + sizeof(ORIGINATE_IDENTIFIER) - 1;
    *out_packetCount = ntohl(*((uint32_t*)(packet+offset)));
    offset += sizeof(uint32_t);
    auto fileNameLenght = strnlen((char*)(packet+offset),packetSize - offset);
    if (fileNameLenght == packetSize - offset){
        throw std::runtime_error("Malformed initial packet! (You shouldn't see this error.)");
    }
    if (fileNameLenght > maxFilenameLength){
        throw std::runtime_error("Received filename is too long!");
    }
    strcpy(out_filename,(char*)(packet+offset));
    offset += fileNameLenght + 1;
    *out_dataOffset = offset;
}

size_t processContinuingPacket(uint8_t* packet, size_t packetSize){
    return calculateIPv4HeaderOffset(packet,packetSize) + ICMP_ECHO_HEADER_SIZE + sizeof(ORIGINATE_IDENTIFIER) - 1;
}

void renameIfFileExists(char* filename,size_t bufferLenght){
    bool renamed = false;
    for(int i = 0;std::filesystem::exists(filename);i++){
        renamed = true;
        std::cerr << "File " << filename << " already exists. Renaming to ";
        auto endOffset = strlen(filename);
        auto returnCode = snprintf(filename+endOffset,bufferLenght-endOffset,"-%d",i);
        if (returnCode < 0){
            throw std::runtime_error("Encoding error while renaming file.");
        } else if ((size_t)returnCode >= bufferLenght-endOffset) {
            throw std::runtime_error("Exceeded buffer size when renaming file. The received filename may be extremely long.");
        }
    }
    if (renamed){
        std::cerr << filename << "\n";
    }
}

void receiveFile(int socket,bool IPv6){
    uint8_t receiveBuffer[1500];
    auto packetSize = recv(socket,receiveBuffer,sizeof(receiveBuffer),0);
    if (packetSize == -1){
        throw std::runtime_error("An error occured while trying to read from a socket.");
    }
    if (!isMyPacketIPv4(receiveBuffer,packetSize,0,0))
        return;
    
    uint32_t senderAddress;
    uint32_t packetCount;
    char filename[1500];
    size_t dataOffset;
    processInitialTransferPacket(receiveBuffer,packetSize,filename,1500,&packetCount,&dataOffset,&senderAddress);

    renameIfFileExists(filename,sizeof(filename));
    
    auto outputFile = std::ofstream(filename,std::ofstream::binary);
    if (outputFile.fail()){
        throw std::runtime_error("Failed to open ouput file.");
    }

    outputFile.write((char*)receiveBuffer+dataOffset,sizeof(receiveBuffer)-dataOffset);
    if (outputFile.fail()){
        throw std::runtime_error("I/O error when writing file.");
    }
    for (uint32_t expectedPacketNumber = 1;expectedPacketNumber < packetCount;){
        packetSize = recv(socket,receiveBuffer,sizeof(receiveBuffer),0);
        if (packetSize == -1){
            throw std::runtime_error("An error occured while trying to read from a socket.");
        }
        if (isMyPacketIPv4(receiveBuffer,packetSize,expectedPacketNumber,senderAddress)){
            expectedPacketNumber++;
            dataOffset = processContinuingPacket(receiveBuffer,sizeof(receiveBuffer));
            outputFile.write(((char*)receiveBuffer)+dataOffset,sizeof(receiveBuffer)-dataOffset);
            if (outputFile.fail()){
                throw std::runtime_error("I/O error when writing file.");
            }
        }
    }
    outputFile.close();
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
    pollfd polledSockets[2];
    polledSockets[IPV4_SOCKET_OFFSET].fd = IPv4_socket;
    polledSockets[IPV4_SOCKET_OFFSET].events = POLLIN;
    polledSockets[IPV6_SOCKET_OFFSET].fd = IPv6_socket;
    polledSockets[IPV6_SOCKET_OFFSET].events = POLLIN;

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