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

/**
 * @brief Encrypts a block of memory and writes the encrypted output to the out buffer. The amount of encrypted output data MAY be larger than the amount of input data. The areas of memory pointed by in and out must be non-overlapping. 
 * 
 * @param in A pointer to the beginning of a block of memory that is to be encrypted.
 * @param inputSize The size of the block of memory to be encrypted. (In bytes.)
 * @param packetNumber The packet number of of the packet this block of memory belongs to. (Used as an initialization vector.)
 * @param out A pointer to a block of memory where the ciphertext should be written to.
 * @return int The size of the ciphertext. (May be larger than the size of the input.)
 */
int encrypt(const unsigned char* in, size_t inputSize,uint32_t packetNumber,unsigned char* out){
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

    if(1 != EVP_EncryptUpdate(ctx, out, &outputLength, in, inputSize)){
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

/**
 * @brief Decrypts a block of memory and writes the decrypted output to the out buffer. The amount of decrypted output data MAY be smaller than the amount of input data. The areas of memory pointed by in and out must be non-overlapping. 
 * 
 * @param in A pointer to the beginning of a block of memory that is to be decrypted.
 * @param inputSize The size of the block of memory to be decrypted. (In bytes.)
 * @param packetNumber The packet number of of the packet this block of memory belongs to. (Used as an initialization vector.)
 * @param out A pointer to a block of memory where the plaintext should be written to.
 * @return int The size of the plaintext. (May be smaller than the size of the input.)
 */
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

/**
 * @brief Compares the addressed of two sockaddr structures.
 * 
 * @param a A sockaddr structure to be compared.
 * @param b Another sockaddr structure to be compared.
 * @param IPv6 True if the sockaddr structures point to IPv6 addresses (sockaddr_in6); false if they point to IPv4 addresses (sockaddr_in).
 * @return true The compared sockaddr structures have the same address.
 * @return false The compared sockaddr structures don't have the same address.
 */
bool compareAddress(sockaddr* a, sockaddr* b, bool IPv6){
    if (IPv6){
        return memcmp(&(((sockaddr_in6*)a)->sin6_addr), &(((sockaddr_in6*)b)->sin6_addr),sizeof(in6_addr)) == 0;
    } else {
        return ((sockaddr_in*)a)->sin_addr.s_addr == ((sockaddr_in*)b)->sin_addr.s_addr;
    }
}

/**
 * @brief Given the received data of an AF_INET (IPv4) SOCK_RAW socket, calculates the offset at which the IP header ends.
 * 
 * @param IP_packet Pointer to the beginning of received data of an AF_INET (IPv4) SOCK_RAW socket
 * @param size The size of the data pointed to by IP_packet
 * @return size_t The offset at which the IP header ends
 */
size_t calculateIPv4HeaderOffset(void* IP_packet,size_t size){
    if (size < sizeof(iphdr)){
        throw std::runtime_error("IP packet cannot possibly be this small. (You shouldn't see this error.)");
    }
    return ((iphdr*)IP_packet)->ihl * 4;
}

/**
 * @brief Given the received data of an IP SOCK_RAW socket, calculates the offset at which the potentially included IP header ends and the IP payload starts.
 * 
 * @param IP_packet Pointer to the beginning of received data of an IP SOCK_RAW socket
 * @param size The size of the data pointed to by IP_packet
 * @param IPv6 Whether the data was received by an IPv6 (AF_INET6) or IPv4 (AF_INET) socket
 * @return size_t The offset at which the payload starts
 */
size_t calculatePacketIPHeaderOffset(void* IP_packet,size_t size, bool IPv6){
    return (IPv6 ? 0 : calculateIPv4HeaderOffset(IP_packet,size));
}

/**
 * @brief Calculates the ICMP checksum of an ICMP or ICMPv6 packet. The checksum field is skipped when performing the calculation and so it need not be set to zero. The function returns 0 if given an ICMPv6 packet because, contrary to ICMP packets, the operating system must provide the checksum and not the application (see RFC 3542).
 * 
 * @param ICMP_message A pointer to an ICMP or ICMPv6 packet
 * @param len The length of the data pointed by ICMP_message
 * @param IPv6 True if the input is an ICMPv6 packet; false if it is an ICMP packet
 * @return uint16_t The checksum of the ICMP or ICMPv6 packet
 */
uint16_t calculateChecksum(const uint8_t* ICMP_message,size_t len,bool IPv6){
    if (IPv6){
        return 0; //The operating system will provide the checksum. (See RFC 3542.)
    }
    uint32_t sum = 0;
    sum += *(uint16_t*)ICMP_message; //First word -- type and code
    size_t offset = 4; //We set the offset to 4. We move past the first word and the skip over the following, since it's the checksum word, which we need to skip for the computation.
    for(;offset + 1 < len;offset += 2){ //We process each 16-bit word.
        sum += *(uint16_t*)(ICMP_message+offset);
    }
    if (offset < len){ //We process the potentially remaining single byte.
        sum += *(uint8_t*)(ICMP_message+offset);
    }
    return ~((uint16_t)(sum  >> 16) + (uint16_t)(sum & 0xffff));
}

/**
 * @brief Builds an ICMP or ICMPv6 echo-request packet.
 * 
 * @param identifier The value of the id field to be set.
 * @param sequence The value of the sequence field to be set.
 * @param payload A pointer to the payload to be included with the echo-request packet.
 * @param payloadLength The length of the data pointed by the payload pointer.
 * @param out A pointer to where the built echo-request packet should be written.
 * @param IPv6 True if the output should be an ICMPv6 packet; false if it should be na ICMP packet
 * @return size_t The size of the built packet; the value will always be payloadLength + the size of the ICMP or ICMPv6 header (8 bytes)
 */
size_t buildEchoMessage(uint16_t identifier, uint16_t sequence, const void* payload, size_t payloadLength, uint8_t* out,bool IPv6){
    ((icmphdr*)out)->type = IPv6 ? ICMP6_ECHO_REQUEST : ICMP_ECHO;
    ((icmphdr*)out)->code = 0;
    ((icmphdr*)out)->un.echo.id = htons(identifier);
    ((icmphdr*)out)->un.echo.sequence = htons(sequence);
    memcpy(out+ICMP_ECHO_HEADER_SIZE,payload,payloadLength);
    ((icmphdr*)out)->checksum = calculateChecksum((uint8_t*)out,payloadLength+ICMP_ECHO_HEADER_SIZE,IPv6);
    return payloadLength + ICMP_ECHO_HEADER_SIZE;
}

/**
 * @brief Determines if an ICMP packet is the echo-reply packet to a specific echo-request packet. This function skips checking the validity of a checksum.
 * 
 * @param original_ICMP_packet A pointer to an echo-request packet
 * @param receivedPacket A pointer to a 
 * @param originalSize The size of the pointed echo-request packet
 * @param receivedSize The size of the supposed corresponding echo-reply packet
 * @param IPv6 True if packets should be treated as ICMPv6 packets; false if they should be treated as ICMP packets.
 * @return true The received packet is a corresponding reply packet to the supplied echo-request packet.
 * @return false The received packet is not corresponding reply packet to the supplied echo-request packet.
 */
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