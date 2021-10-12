#include <fstream>
#include "addressResolution.hpp"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdexcept>
#include <errno.h>
#include <cstring>

const char* ORIGINATE_IDENTIFIER = "riko";
const char* ANSWER_IDENTIFIER = "regu";
const size_t IDENTIFIER_LENGTH = 4;
const size_t PACKET_COUNT_LENGTH = sizeof(uint32_t);

uint32_t determinePacketCount(const char* filename, size_t fileSize, size_t payloadLength){
    if (payloadLength < (PACKET_COUNT_LENGTH)) {
        throw std::runtime_error("Payload length too small to contain identifier. (You shouldn't see this error.)");
    }
    payloadLength -= IDENTIFIER_LENGTH;
    
    size_t firstPayloadExtraLength = PACKET_COUNT_LENGTH + strlen(filename) + 1;
    if (payloadLength < firstPayloadExtraLength){
        throw std::runtime_error("Payload length too small to contain packet count and filename. If you are using extremely large filenames, use a shorter filename; otherwise, you shouldn't see this error.");
    }

    if (fileSize < (payloadLength - firstPayloadExtraLength)){
        return 1;
    }

    fileSize -= payloadLength - firstPayloadExtraLength;
    return (fileSize / payloadLength) + ((fileSize % payloadLength) != 0) + 1;
}

void buildOriginatePayload(const char* filename, std::ifstream & file, uint8_t* out,size_t payloadLenght){
    size_t offset = 0;
    int returnCode = snprintf((char*)out+offset,payloadLenght - offset,"riko");
    if (returnCode < 0){
        throw std::runtime_error("Encoding error when building payload");
    }
    if (returnCode >= payloadLenght - offset){
        throw std::runtime_error("Payload buffer too short while adding payload identifier. (You shouldn't see this error.)");
    }
    offset += 4;
    
    returnCode = snprintf((char*)out+offset,payloadLenght - offset,"%s",filename);
    if (returnCode < 0){
        throw std::runtime_error("Encoding error when building payload");
    }
    if (returnCode >= payloadLenght - offset){
        throw std::runtime_error("Filename too long! Use a shorter filename!");
    }
}

void sendFile_IPv4(std::ifstream & file,const char* filename,Address* address){
    auto echoSocket = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    if (echoSocket == -1){
        if (errno == EACCES){
            throw std::runtime_error("This programs needs to be run with super-user privileges.");
        } else {
            throw std::runtime_error(strerror(errno));
        }
    }
    
    sockaddr_in echoAddress;
    echoAddress.sin_family = AF_INET;
    echoAddress.sin_port = IPPROTO_ICMP;
    mempcpy(&echoAddress.sin_addr,&address->address->sa_data,sizeof(echoAddress.sin_addr));



}