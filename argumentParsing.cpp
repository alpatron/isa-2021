#include "argumentParsing.hpp"
#include <unistd.h>
#include <stdexcept>

/**
 * @brief Parses command-line arguments and saves their value to the args Arguments structure. This function calls getopt and thus modifies global variables used by getopt.
 * 
 * @param argc argc from the main function
 * @param argv argv from the main funciton
 * @param args a pointer to an Arguments structure
 * 
 * @throws std::runtime_error If given invalid user input or if getopt fails.
 * 
 */
void parseCommandLineArguments(int argc, char* argv[], Arguments* args) {
    args->listeningMode = false;
    args->fileName = nullptr;
    args->hostName = nullptr;

    int c;
    while ((c = getopt(argc,argv,"r:s:l")) != -1){
        switch (c) {
            case 'l':
                args->listeningMode = true;
                break;
            case 'r':
                args->fileName = optarg;
                break;
            case 's':
                args->hostName = optarg;
                break;
            case '?':
                throw std::runtime_error("Invalid input.");
            default:
                throw std::runtime_error("Fatal error in getopt. This message should never be seen.");
        }
    };

    if (argc != optind){
        throw std::runtime_error("Invalid input.");
    }

    if (args->listeningMode){
        if (args->fileName != nullptr || args->hostName != nullptr){
            throw std::runtime_error("File and or host name was supplied while listening mode was specified. Listening mode takes no arguments.");
        }
    } else {
        if (args->fileName == nullptr || args->hostName == nullptr){
            throw std::runtime_error("File and or host name was not supplied while sending mode was specified. Sending mode takes both arguments.");
        }
    }

}