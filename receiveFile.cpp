#include "ICMP_Message.hpp"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdexcept>
#include <cstring>

[[noreturn]] void receiveFiles(){
    auto IPv4_socket = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    if (IPv4_socket == -1){
        if (errno == EACCES){
            throw std::runtime_error("This programs needs to be run with super-user privileges.");
        } else {
            throw std::runtime_error(strerror(errno));
        }
    }
    auto IPv6_sokcet = socket(AF_INET6,SOCK_RAW,IPPROTO_ICMPV6);
    if (IPv6_sokcet == -1){
        if (errno == EACCES){
            throw std::runtime_error("This programs needs to be run with super-user privileges.");
        } else {
            throw std::runtime_error(strerror(errno));
        }
    }

    
}