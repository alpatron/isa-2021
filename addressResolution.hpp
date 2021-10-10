#ifndef ADDRESS_RESOLUTION_H
#define ADDRESS_RESOLUTION_H

#include <netdb.h>

typedef struct {
    int addressFamily;
    socklen_t addressLenght;
    sockaddr *address;
    addrinfo* rawAddrinfo;
} Address;

void resolveNameToAddress(const char* host,Address* address);
void freeAddress(Address* address);

#endif