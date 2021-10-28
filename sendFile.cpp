#include "sendFile.hpp"
#include <fstream>
#include "tools.hpp"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdexcept>
#include <errno.h>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <unistd.h>
#include <algorithm>
#include <netinet/ip.h>
#include <chrono>

const int RESEND_ON_FAIL_WAIT = 1;

const size_t PACKET_COUNT_LENGTH = sizeof(uint32_t);
const size_t PAYLOAD_BUFFER_SIZE = 1400;
const size_t ENCRYPTED_PAYLOAD_BUFFER_SIZE = PAYLOAD_BUFFER_SIZE + 64;
const size_t ICMP_MESSAGE_BUFFER_SIZE = ENCRYPTED_PAYLOAD_BUFFER_SIZE + ICMP_ECHO_HEADER_SIZE;
const size_t RECEIVE_BUFFER_SIZE = std::max((size_t)1500,PAYLOAD_BUFFER_SIZE + ICMP_ECHO_HEADER_SIZE);
const timeval SOCKET_RECEIVE_TIMEOUT = {30,0};

/**
 * @brief Checks whether a given packet is a corresponding response packet to a given echo-request packet.
 * 
 * @param original_ICMP_packet A pointer to a sent-out echo-request packet
 * @param receivedPacket A pointer to a received packet
 * @param originalSize The size of the data pointed by original_ICMP_packet
 * @param receivedSize The size of the data pointed by receivedPacket
 * @param IPv6 True if the packet was received on an IPv6 (AF_INET6) socket; false if the packet was received on an IPv4 (AF_INET) socket
 * @return true The given packet is a corresponding response packet to the given echo-request packet
 * @return false The given packet is not a corresponding response packet to the given echo-request packet
 */
bool isMyPacket(uint8_t* original_ICMP_packet,uint8_t* receivedPacket,size_t originalSize, size_t receivedSize, bool IPv6){
    if (IPv6){
        return isMyReplyICMP_Packet(original_ICMP_packet,receivedPacket,originalSize,receivedSize,IPv6);
    } else {
        auto receivedPacketIPHeaderOffset = calculateIPv4HeaderOffset(receivedPacket,receivedSize);
        auto receivedICMP_packet = receivedPacket + receivedPacketIPHeaderOffset;
        return isMyReplyICMP_Packet(original_ICMP_packet,receivedICMP_packet,originalSize,receivedSize-receivedPacketIPHeaderOffset,IPv6);
    }
}

/**
 * @brief Given a file length, a filename, and the maximum size of a payload, calculates the number of packets needed to transmit the file.
 * 
 * @param filename The name of the file that will be transmitted
 * @param fileSize The size of the file that will be transmitted
 * @param payloadLength The maximum size of the payload
 * @return uint32_t The number of packets that the file transfer will need to be fragmented into
 */
uint32_t calculatePacketCount(const char* filename, std::uintmax_t fileSize, size_t payloadLength){
    if (payloadLength < (sizeof(PACKET_IDENTIFIER) - 1)) {
        throw std::runtime_error("Payload length too small to contain identifier. (You shouldn't see this error.)");
    }
    payloadLength -= sizeof(PACKET_IDENTIFIER) - 1;
    
    size_t firstPayloadExtraLength = PACKET_COUNT_LENGTH + strlen(filename) + 1;
    if (payloadLength < firstPayloadExtraLength){
        throw std::runtime_error("Payload length too small to contain packet count and filename. If you are using extremely large filenames, use a shorter filename; otherwise, you shouldn't see this error.");
    }

    if (fileSize < (payloadLength - firstPayloadExtraLength)){
        return 1;
    }

    fileSize -= payloadLength - firstPayloadExtraLength;
    return (fileSize / payloadLength) + ((fileSize % payloadLength) != 0) + 1; //Ceiling division + the first packet
}

/**
 * @brief Builds the initial payload (the payload contained in the first packet). The function does not encrypt the payload.
 * 
 * @param filename The filename that will be transmitted
 * @param file An open std::ifstream object from which to read file contents that should be tranmistted
 * @param packetCount The total number of packets in the transmission
 * @param payloadLength The maximum length of a payload (there will be no more than payloadLength bytes written)
 * @param out A pointer to a block of memory where the built payload should be written to
 * @return size_t The size of the generated payload
 */
size_t buildOriginatePayload(const char* filename, std::ifstream & file, uint32_t packetCount, size_t payloadLength,  uint8_t* out){
    size_t offset = 0;
    
    //Writing the packet identifier
    int returnCode = snprintf((char*)out+offset,payloadLength - offset,PACKET_IDENTIFIER);
    if (returnCode < 0){
        throw std::runtime_error("Encoding error when building payload");
    }
    if ((size_t)returnCode >= payloadLength - offset){
        throw std::runtime_error("Payload buffer too short while adding payload identifier. (You shouldn't see this error.)");
    }
    offset += 4;

    //Writing the packet count
    if(4 >= payloadLength - offset){
        throw std::runtime_error("Payload buffer too short while adding packet count. (You shouldn't see this error.)");
    }
    *((uint32_t*)(out+offset)) = htonl(packetCount);
    offset += 4;

    //Writing the filename
    returnCode = snprintf((char*)out+offset,payloadLength - offset,"%s",filename);
    if (returnCode < 0){
        throw std::runtime_error("Encoding error when building payload");
    }
    if ((size_t)returnCode >= payloadLength - offset){
        throw std::runtime_error("Filename too long! Use a shorter filename!");
    }
    offset += strlen(filename) + 1;

    //Writing file data in the rest of the payload
    file.read((char*)out+offset,payloadLength - offset);
    if(file.fail() && !file.eof()){
        throw std::runtime_error("Error while reading file");
    }
    return offset + file.gcount();
}

/**
 * @brief Builds a payload for a non-initial packet.
 * 
 * @param file An open std::ifstream object from which to read file contents that should be tranmistted
 * @param payloadLength The maximum length of a payload (there will be no more than payloadLength bytes written)
 * @param out A pointer to a block of memory where the built payload should be written to
 * @return size_t The size of the generated payload
 */
size_t buildContinuePayload(std::ifstream & file, size_t payloadLength,  uint8_t* out){
    size_t offset = 0;
    int returnCode = snprintf((char*)out+offset,payloadLength - offset,PACKET_IDENTIFIER);
    if (returnCode < 0){
        throw std::runtime_error("Encoding error when building payload");
    }
    if ((size_t)returnCode >= payloadLength - offset){
        throw std::runtime_error("Payload buffer too short while adding payload identifier. (You shouldn't see this error.)");
    }
    offset += 4;

    file.read((char*)out+offset,payloadLength - offset);
    if(file.fail() && !file.eof()){
        throw std::runtime_error("Error while reading file");
    }
    return offset + file.gcount();
}

/**
 * @brief Sends a file using the covert echo protocol (which is reliable).
 * 
 * @param filepath_cstring A path to a file that should be transmitted
 * @param address An Address object specifying which address to send the file to
 * @param IPv6 True if the address is na IPv6 address; false if it is an IPv4 address
 */
void sendFile(const char* filepath_cstring,Address* address,bool IPv6){
    ssize_t errorCode;
    uint8_t payloadBuffer[PAYLOAD_BUFFER_SIZE];
    uint8_t encryptedPayloadBuffer[PAYLOAD_BUFFER_SIZE];
    uint8_t sendBuffer [ICMP_MESSAGE_BUFFER_SIZE];
    uint8_t receiveBuffer[RECEIVE_BUFFER_SIZE];
    sockaddr_storage receivedFromAddress;
    socklen_t receivedAddressLength;
    auto echoSocket = socket(IPv6 ? AF_INET6 : AF_INET,SOCK_RAW,IPv6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP);
    if (echoSocket == -1){
        if (errno == EPERM){
            throw std::runtime_error("This programs needs to be run with super-user privileges.");
        } else {
            throw std::runtime_error(strerror(errno));
        }
    }
    setsockopt(echoSocket,SOL_SOCKET,SO_RCVTIMEO,&SOCKET_RECEIVE_TIMEOUT,sizeof(SOCKET_RECEIVE_TIMEOUT));

    sockaddr_in echoAddress;
    echoAddress.sin_family = IPv6 ? AF_INET6 : AF_INET;
    echoAddress.sin_port = IPv6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP;
    mempcpy(&echoAddress.sin_addr,&address->address->sa_data,address->addressLength);

    auto file = std::ifstream(filepath_cstring,std::ifstream::binary);
    if (file.fail()){
        throw std::runtime_error("Could not open input file");
    }
    auto filepath = std::filesystem::path(filepath_cstring);
    auto filename = filepath.filename();
    auto filesize = std::filesystem::file_size(filepath);

    auto packetCount = calculatePacketCount(filename.c_str(),filesize,PAYLOAD_BUFFER_SIZE);
    for(uint32_t packetNumber = 0;packetNumber<packetCount;packetNumber++){
        auto payloadLength = packetNumber == 0 ? buildOriginatePayload(filename.c_str(),file,packetCount,PAYLOAD_BUFFER_SIZE,payloadBuffer) : buildContinuePayload(file,PAYLOAD_BUFFER_SIZE,payloadBuffer);
        auto encryptedPayloadLength = encrypt(payloadBuffer,payloadLength,packetNumber,encryptedPayloadBuffer);
        auto echoLength = buildEchoMessage((uint16_t)((packetNumber & 0xffff0000) >> 16),(uint16_t)(packetNumber & 0xffff),encryptedPayloadBuffer,encryptedPayloadLength,sendBuffer,IPv6);
        while(true){
            while((size_t)(errorCode = sendto(echoSocket,sendBuffer,echoLength,0,address->address,address->addressLength)) != echoLength){
                std::cerr << strerror(errno) << "\n";
                std::cerr << "Failed to send packet. Waiting and retrying. Packet " << packetNumber + 1 << "/" << packetCount << "\n";
                sleep(RESEND_ON_FAIL_WAIT);
            }
            auto sendTime = std::chrono::system_clock::now();
            bool gotMyPacket = false;
            do{
                receivedAddressLength = sizeof(receivedFromAddress);
                auto receivedBytes = recvfrom(echoSocket,receiveBuffer,sizeof(receiveBuffer),0,(sockaddr*)&receivedFromAddress,&receivedAddressLength);
                if (compareAddress(address->address,(sockaddr*)&receivedFromAddress,IPv6) && isMyPacket(sendBuffer,receiveBuffer,echoLength,receivedBytes,IPv6)){
                    gotMyPacket = true;
                }
            }while(!gotMyPacket &&
                   std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - sendTime).count() < SOCKET_RECEIVE_TIMEOUT.tv_sec*1000);
            if (gotMyPacket){
                break;
            } else {
                std::cerr << "Did not receive reply packet in time. Resending. Packet " << packetNumber + 1 << "/" << packetCount << "\n";
            }
        }
    }

    if(close(echoSocket) == -1){
        throw std::runtime_error(strerror(errno));
    }     
}