#ifndef ADDRESS_RESOLUTION_H
#define ADDRESS_RESOLUTION_H

#include <netdb.h>

/**
 * @brief A wrapper for the structure returned by getaddrinfo.
 * 
 */
typedef struct {
    int addressFamily;
    socklen_t addressLength;
    sockaddr *address;
    addrinfo* rawAddrinfo;
} Address;

void resolveNameToAddress(const char* host,Address* address);
void freeAddress(Address* address);

#endif