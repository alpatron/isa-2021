#ifndef SEND_FILE_HPP
#define SEND_FILE_HPP

#include "addressResolution.hpp"

void sendFile(const char* filepath_cstring,Address* address,bool IPv6);

#endif