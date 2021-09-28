#include <unistd.h>
#include <iostream>

int main (int argc, char* argv[]){
    bool listenMode = false;
    char* fileName = nullptr;
    char* hostName = nullptr; //TODO: I should probably change the name here to something more accurate.
    int c;

    while ((c = getopt(argc,argv,"r:s:l")) != -1){
        switch (c) {
            case 'l':
                listenMode = true;
                break;
            case 'r':
                fileName = optarg;
                break;
            case 's':
                hostName = optarg;
                break;
            case '?':
                std::cout << "You done messed up! I ain't understanding what you giving me, chief!\n";
                return -1;
            default:
                std::cout << "Fatal error. I guess. \n";
                return -1;
        }
    };
    
    if (listenMode){
        if (fileName != nullptr || hostName != nullptr){
            std::cout << "You done messed up. We ain't need no file or host name for the server mode, chief.\n";
            return -1;
        }
    } else {
        if (fileName == nullptr || hostName == nullptr){
            std::cout << "You done messed up. We ai need a file and host name for the sending mode, chief.\n";
            return -1;
        }
    }

    std::cout << "All is well!\n";
    std::cout << "Mode:" << (listenMode ? "receiver" : "sender") << "\n";
    if (!listenMode){
        std::cout << "File name:" << fileName << "\n";
        std::cout << "Host name:" << hostName << "\n";
    }
    return 0;
}