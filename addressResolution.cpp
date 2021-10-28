#include "addressResolution.hpp"
#include <sys/socket.h>
#include <netdb.h>
#include <stdexcept>

/**
 * @brief Given a hostname understood by the 'getaddrinfo' function, resolves it to an IPv4 or IPv6 address and stores it in the Address wrapper structure. The address object must be freed with the 'freeAddress' function after use. This function is merely a wrapper for the 'getaddrinfo' function.
 * 
 * @exception std::runtime_error Thrown if address resolution fails or if the address is resolved to a non-IP address. In this case, the Address structure may be modified but isn't necessary to be freed.
 * 
 * @param host A C-style string to be resolved to an IPv4/6 network address.
 * @param address A pointer to an Address object into which the resolved address is stored. If this function is executed successfully, the Address structure must be freed by the freeAddress' function.
 */
void resolveNameToAddress(const char* host,Address* address){
    addrinfo* result;
    int returnCode;

    if ((returnCode = getaddrinfo(host,NULL,NULL,&result)) != 0){
        throw std::runtime_error(gai_strerror(returnCode));
    }
    
    if (result->ai_family == AF_INET || result->ai_family == AF_INET6){
        address->addressFamily = result->ai_family;
    } else {
        throw std::runtime_error("Fatal unexpected error!"); //I don't think that anything else than AF_INET and AF_INET6 can even be returned from the getaddrinfo function, but just to be sure, I handle for the unforeseen circumstance.
        freeaddrinfo(result);;
    }

    address->addressLength = result->ai_addrlen;
    address->address = result->ai_addr;
    address->rawAddrinfo = result;
}

/**
 * @brief Frees the Address structure after it was populated by the resolveNameToAddress command. 
 * 
 * @param address A pointer to an Address structure.
 */
void freeAddress(Address* address){
    freeaddrinfo(address->rawAddrinfo);
}
