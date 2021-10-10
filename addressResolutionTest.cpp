#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <iostream>

int main(int argc, char* argv[]){
    addrinfo* result;

    int returnCode = getaddrinfo(argv[1],NULL,NULL,&result);

    return 0;
}