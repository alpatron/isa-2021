#include "tools.hpp"
#include <stdint.h>
#include <cstddef>
#include <arpa/inet.h>
#include <cstring>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <stdexcept>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int encrypt(const unsigned char* input, size_t inputSize,uint32_t packetNumber,unsigned char* out){
    EVP_CIPHER_CTX *ctx;
    
    const unsigned char* encryptionKey = (const unsigned char *)"xrucky01xrucky0";
    uint64_t initialisationVector[2];
    initialisationVector[0] = packetNumber;
    initialisationVector[1] = packetNumber;
    int outputLengthTmp;
    int outputLength;


    if(!(ctx = EVP_CIPHER_CTX_new())){
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Error while encrypting!");
    }

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, encryptionKey, (unsigned char *)initialisationVector)){
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Error while encrypting!");
    }

    if(1 != EVP_EncryptUpdate(ctx, out, &outputLength, input, inputSize)){
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Error while encrypting!");
    }

    if(1 != EVP_EncryptFinal_ex(ctx, out + outputLength, &outputLengthTmp)){
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Error while encrypting!");
    }  
    
    EVP_CIPHER_CTX_free(ctx);

    return outputLength + outputLengthTmp;
}

int decrypt(const unsigned char* input, size_t inputSize,uint32_t packetNumber,unsigned char* out){
    EVP_CIPHER_CTX *ctx;
    
    const unsigned char* encryptionKey = (const unsigned char *)"xrucky01xrucky0";
    uint64_t initialisationVector[2];
    initialisationVector[0] = packetNumber;
    initialisationVector[1] = packetNumber;
    int outputLengthTmp;
    int outputLength;


    if(!(ctx = EVP_CIPHER_CTX_new())){
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error(ERR_error_string(ERR_get_error(),NULL));
    }

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, encryptionKey, (unsigned char *)initialisationVector)){
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error(ERR_error_string(ERR_get_error(),NULL));
    }

    if(1 != EVP_DecryptUpdate(ctx, out, &outputLength, input, inputSize)){
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error(ERR_error_string(ERR_get_error(),NULL));
    }

    if(1 != EVP_DecryptFinal_ex(ctx, out + outputLength, &outputLengthTmp)){
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error(ERR_error_string(ERR_get_error(),NULL));
    }  
    
    EVP_CIPHER_CTX_free(ctx);

    return outputLength + outputLengthTmp;
}

bool compareAddress(sockaddr* a, sockaddr* b, bool IPv6){
    if (IPv6){
        return memcmp(&(((sockaddr_in6*)a)->sin6_addr), &(((sockaddr_in6*)b)->sin6_addr),sizeof(in6_addr)) == 0;
    } else {
        return ((sockaddr_in*)a)->sin_addr.s_addr == ((sockaddr_in*)b)->sin_addr.s_addr;
    }
}

size_t calculateIPv4HeaderOffset(void* IP_packet,size_t size){
    if (size < sizeof(iphdr)){
        throw std::runtime_error("IP packet cannot possibly be this small. (You shouldn't see this error.)");
    }
    return ((iphdr*)IP_packet)->ihl * 4;
}

size_t calculatePacketIPHeaderOffset(void* IP_packet,size_t size, bool IPv6){
    return (IPv6 ? 0 : calculateIPv4HeaderOffset(IP_packet,size));
}

uint16_t calculateChecksum(const uint8_t* ICMP_message,size_t len,bool IPv6){
    if (IPv6){
        return 0;
    }
    uint32_t sum = 0;
    sum += *(uint16_t*)ICMP_message; //First word -- type and code
    size_t offset = 4; //We set the offset to 4. We move past the first word and the skip over the following, since it's the checksum word, which we need to skip for the computation.
    for(;offset + 1 < len;offset += 2){
        sum += *(uint16_t*)(ICMP_message+offset);
    }
    if (offset < len){
        sum += *(uint8_t*)(ICMP_message+offset);
    }
    return ~((uint16_t)(sum  >> 16) + (uint16_t)(sum & 0xffff));
}

size_t buildEchoMessage(uint16_t identifier, uint16_t sequence, const void* payload, size_t payloadLenght, uint8_t* out,bool IPv6){
    ((icmphdr*)out)->type = IPv6 ? ICMP6_ECHO_REQUEST : ICMP_ECHO;
    ((icmphdr*)out)->code = 0;
    ((icmphdr*)out)->un.echo.id = htons(identifier);
    ((icmphdr*)out)->un.echo.sequence = htons(sequence);
    memcpy(out+ICMP_ECHO_HEADER_SIZE,payload,payloadLenght);
    ((icmphdr*)out)->checksum = calculateChecksum((uint8_t*)out,payloadLenght+ICMP_ECHO_HEADER_SIZE,IPv6);
    return payloadLenght + ICMP_ECHO_HEADER_SIZE;
}

bool isMyReplyICMP_Packet(uint8_t* original_ICMP_packet,uint8_t* receivedPacket,size_t originalSize, size_t receivedSize,bool IPv6){
    if (originalSize != receivedSize){
        return false;
    }
    if (((icmphdr*)receivedPacket)->type != (IPv6 ? ICMP6_ECHO_REPLY : ICMP_ECHOREPLY) || ((icmphdr*)receivedPacket)->code != 0){
        return false;
    }
    if (((icmphdr*)receivedPacket)->un.echo.id != ((icmphdr*)original_ICMP_packet)->un.echo.id ||
        ((icmphdr*)receivedPacket)->un.echo.sequence != ((icmphdr*)original_ICMP_packet)->un.echo.sequence){
        return false;
    }
    return memcmp(original_ICMP_packet+ICMP_ECHO_HEADER_SIZE,receivedPacket+ICMP_ECHO_HEADER_SIZE,originalSize-ICMP_ECHO_HEADER_SIZE) == 0;
}