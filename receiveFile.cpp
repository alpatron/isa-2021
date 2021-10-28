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
#include <netinet/icmp6.h>

#define IPV4_SOCKET_OFFSET 0
#define IPV6_SOCKET_OFFSET 1

/**
 * @brief Determines if a (decrypted) ICMP or ICMPv6 packet is part of file transmission.
 * 
 * The function determines this by:
 * 1. checking if the ICMP header is correctly set, i.e. whether it's a echo-request packet and whether the id and sequence fields match the expected packet number
 * 2. checking if the file-transmission identifier is present
 * 3. if an initial packet is expected, checking if a binary zero is present in the filename field
 * 
 * @param packet A pointer to an ICMP or ICMPv6 packet with a decrypted payload
 * @param packetSize The length of the data pointed to by packet
 * @param expectedPacketNumber The expected packet number to be received.
 * @param IPv6 True if an ICMPv6 packet is expected; false if an ICMP packet is expected.
 * @return true The packet is part of a file transmission.
 * @return false The packet is not part of a file transmission. (It's an unrelated packet.)
 */
bool isMyPacket(uint8_t* packet,size_t packetSize,uint32_t expectedPacketNumber,bool IPv6){
    size_t offset = 0;
    if (packetSize - offset < sizeof(icmphdr)){
        throw std::runtime_error("ICMP packet cannot possibly be this small. (You shouldn't see this error.)");
    }
    if (((icmphdr*)(packet+offset))->type != (IPv6 ? ICMP6_ECHO_REQUEST : ICMP_ECHO) || ((icmphdr*)(packet+offset))->code != 0){
        return false;
    }
    if (((icmphdr*)(packet+offset))->un.echo.sequence != htons((uint16_t)((expectedPacketNumber & 0xffff))) || ((icmphdr*)(packet+offset))->un.echo.id != (uint16_t)((expectedPacketNumber & 0xffff0000) >> 16)){
        return false;
    }
    offset += ICMP_ECHO_HEADER_SIZE;
    
    if (packetSize - offset < sizeof(PACKET_IDENTIFIER))
        return false;
    if (memcmp(packet+offset,PACKET_IDENTIFIER,sizeof(PACKET_IDENTIFIER)-1) != 0){ //Terminating binary zero is not included in a packet.
        return false;
    }
    offset += sizeof(PACKET_IDENTIFIER)-1;

    if (expectedPacketNumber == 0){ //The initial packet contains packet-count and a filename fields. If the filename field does not contain a null terminator, it's a malformed packet and a buffer over-read would happen.
        offset += sizeof(uint32_t); // Skip the packet-count field.
        auto fileNameLength = strnlen((char*)(packet+offset),packetSize - offset);
        if (fileNameLength == packetSize - offset){
            return false;
        }
    }
    return true;
}

/**
 * @brief Decrypts the payload of an ICMP or ICMPv6 packet. This function does not alter the ICMP or ICMPv6 header.
 * 
 * @exception std::runtime_error There was a failure with the decryption. This mostly means that the received packet was not part of a file transmission.
 * 
 * @param packet A pointer to an ICMP or ICMPv6 packet
 * @param packetSize The length of the data pointed to by packet
 * @param decryptedPacket A pointer to an area of memory where the decrypted packet should be written to
 * @param packetNumber The packet number of the packet
 * @return size_t The number of bytes written (this may be lower than the number of bytes on input)
 */
size_t decryptPacketContent(uint8_t* packet, size_t packetSize, uint8_t* decryptedPacket, uint32_t packetNumber){
    memcpy(decryptedPacket,packet,ICMP_ECHO_HEADER_SIZE);
    auto decryptedPayloadLength = decrypt(packet+ICMP_ECHO_HEADER_SIZE,packetSize-ICMP_ECHO_HEADER_SIZE,packetNumber,decryptedPacket+ICMP_ECHO_HEADER_SIZE);
    return ICMP_ECHO_HEADER_SIZE + decryptedPayloadLength;
}

/**
 * @brief Given a valid decrypted initial ICMP or ICMPv6 file-transmission packet, returns the offset at which the data part of the payload starts, alongside the file name and packet count of the transimssion.
 * 
 * @exception std::runtime_error Thrown if the received filename is larger than the supplied buffer of if the supplied packet is malformed.
 * 
 * @param packet A pointer to valid decrypted initial ICMP or ICMPv6 file-transmission packet
 * @param packetSize The size of the data pointed to by packet
 * @param out_filename A pointer to where the filename should be written to
 * @param maxFilenameLength The size of the out_filename buffer; if the received filename is larger than the size of the buffer, an exception is thrown.
 * @param out_packetCount A pointer to where the packet count of the transmission should be written to
 * @return size_t The offset at which the data portion of the packet starts
 */
size_t processInitialTransferPacket(uint8_t* packet, size_t packetSize, char* out_filename, size_t maxFilenameLength, uint32_t* out_packetCount){
    auto offset = ICMP_ECHO_HEADER_SIZE + sizeof(PACKET_IDENTIFIER) - 1;
    *out_packetCount = ntohl(*((uint32_t*)(packet+offset)));
    offset += sizeof(uint32_t);
    auto filenameLength = strnlen((char*)(packet+offset),packetSize - offset);
    if (filenameLength == packetSize - offset){
        throw std::runtime_error("Malformed initial packet! (You shouldn't see this error.)");
    }
    if (filenameLength > maxFilenameLength){
        throw std::runtime_error("Received filename is too long!");
    }
    strcpy(out_filename,(char*)(packet+offset));
    offset += filenameLength + 1; //Skip past the null terminator.
    return offset;
}

/**
 * @brief Given a filename, checks if it exists in the current working directory, and if it does, renames it to a unused filename.
 * 
 * @exception std::runtime_error Couldn't rename the filename to a size less than the size of the supplied buffer or an error occurred in a string operation .
 * 
 * @param filename A pointer to the filename that should be potentially renamed. The result will be written in this same buffer.
 * @param bufferLength The size of the filename buffer.
 */
void renameIfFileExists(char* filename,size_t bufferLength){
    if (!std::filesystem::exists(filename)){
        return;
    }
    std::cerr << "File " << filename << " already exists. Renaming to ";
    auto endOffset = strlen(filename);
    for(int i = 0;std::filesystem::exists(filename);i++){
        auto returnCode = snprintf(filename+endOffset,bufferLength-endOffset,"-%d",i);
        if (returnCode < 0){
            throw std::runtime_error("Encoding error while renaming file.");
        } else if ((size_t)returnCode >= bufferLength-endOffset) {
            throw std::runtime_error("Exceeded buffer size when renaming file. The received filename may be extremely long.");
        }
    }
    std::cerr << filename << "\n";
}

/**
 * @brief Receives (or tries to receive) a file.
 * 
 * The functions reads data from a socket.
 * The function checks if the first packet is a valid initial transmission packet and if it is, receives the potential rest of the file tranmission and saves it (potentially renaming the file if it the filename already exists).
 * If the first packet is not a valid packet, this function returns having processed the first packet.
 * This function does not send any echo-response packets of its own; it relies on the built-in OS service.
 * 
 * @param socket An open socket descriptor on which to receive packets. (Should be a SOCK_RAW with IPPROTO_ICMP set.)
 * @param IPv6 True if the socket is an IPv6 (AF_INET6) socket; false if it is an IPv4 (AF_INET) socket.
 */
void receiveFile(int socket,bool IPv6){
    uint8_t receiveBuffer[1500];
    uint8_t decryptedBuffer[1500];
    sockaddr_storage expectedAddress;
    socklen_t expectedAddressLength = sizeof(expectedAddress);
    size_t decryptedPacketSize;
    auto packetSize = recvfrom(socket,receiveBuffer,sizeof(receiveBuffer),0,(sockaddr*)&expectedAddress,&expectedAddressLength);
    if (packetSize == -1){
        throw std::runtime_error("An error occurred while trying to read from a socket.");
    }
    auto IP_headerOffset = calculatePacketIPHeaderOffset(receiveBuffer,packetSize,IPv6);
    try{
        decryptedPacketSize = decryptPacketContent(receiveBuffer+IP_headerOffset,packetSize-IP_headerOffset,decryptedBuffer,0);
    } catch (std::runtime_error& e){
        return;
    }
    if (!isMyPacket(decryptedBuffer,decryptedPacketSize,0,IPv6))
        return;
    
    sockaddr_storage senderAddress;
    socklen_t senderAddressLength;
    uint32_t packetCount;
    char filename[1500];
    size_t dataOffset = processInitialTransferPacket(decryptedBuffer,decryptedPacketSize,filename,1500,&packetCount);
    std::cerr << "Started receiving transfer of file: " << filename << "\n";
    renameIfFileExists(filename,sizeof(filename));
    
    auto outputFile = std::ofstream(filename,std::ofstream::binary);
    if (outputFile.fail()){
        throw std::runtime_error("Failed to open output file.");
    }

    outputFile.write((char*)decryptedBuffer+dataOffset,decryptedPacketSize-dataOffset);
    if (outputFile.fail()){
        throw std::runtime_error("I/O error when writing file.");
    }
    dataOffset = ICMP_ECHO_HEADER_SIZE + sizeof(PACKET_IDENTIFIER) - 1;
    for (uint32_t expectedPacketNumber = 1;expectedPacketNumber < packetCount;){
        senderAddressLength = sizeof(senderAddress);
        packetSize = recvfrom(socket,receiveBuffer,sizeof(receiveBuffer),0,(sockaddr*)&senderAddress,&senderAddressLength);
        if (packetSize == -1){
            throw std::runtime_error("An error occurred while trying to read from a socket.");
        }
        IP_headerOffset = calculatePacketIPHeaderOffset(receiveBuffer,packetSize,IPv6);
        try{
            decryptedPacketSize = decryptPacketContent(receiveBuffer+IP_headerOffset,packetSize-IP_headerOffset,decryptedBuffer,expectedPacketNumber);
        } catch (std::runtime_error& e) {
            continue;
        }
        if (compareAddress((sockaddr*)&expectedAddress,(sockaddr*)&senderAddress,IPv6) && isMyPacket(decryptedBuffer,decryptedPacketSize,expectedPacketNumber,IPv6)){
            expectedPacketNumber++;
            outputFile.write(((char*)decryptedBuffer)+dataOffset,decryptedPacketSize-dataOffset);
            if (outputFile.fail()){
                throw std::runtime_error("I/O error when writing file.");
            }
        }
    }
    outputFile.close();
    std::cerr << "File transfer complete.\n";
}

/**
 * @brief In an infinite loop checks if any ICMP or ICMPv6 packets have been received and processes any incoming file transmissions.
 * 
 */
[[noreturn]] void receiveFiles(){
    auto IPv4_socket = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    if (IPv4_socket == -1){
        if (errno == EPERM){
            throw std::runtime_error("This programs needs to be run with super-user privileges.");
        } else {
            throw std::runtime_error(strerror(errno));
        }
    }
    auto IPv6_socket = socket(AF_INET6,SOCK_RAW,IPPROTO_ICMPV6);
    if (IPv6_socket == -1){
        if (errno == EPERM){
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
        if(polledSockets[IPV4_SOCKET_OFFSET].revents & POLLIN){
            receiveFile(IPv4_socket,false);
        } else if (polledSockets[IPV6_SOCKET_OFFSET].revents & POLLIN){
            receiveFile(IPv6_socket,true);
        } else if (polledSockets[IPV4_SOCKET_OFFSET].revents & POLLERR || polledSockets[IPV6_SOCKET_OFFSET].revents & POLLERR) {
            continue;
        } else {
            throw std::runtime_error("You should never see this error. If you see this line, something is horribly broken.");
        }
    }
}