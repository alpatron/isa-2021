#include "exitCodes.hpp"
#include "argumentParsing.hpp"
#include "addressResolution.hpp"
#include "sendFile.hpp"
#include "receiveFile.hpp"
#include <iostream>

int main (int argc, char* argv[]){
    Arguments arguments;
    Address address;
    try{
        parseCommandLineArguments(argc,argv,&arguments);
    }
    catch (std::runtime_error& e){
        std::cerr << e.what() << "\n";
        return EXIT_ERROR_COMMAND_LINE_ARGUMENT;
    }

    if(arguments.listeningMode){
        try{
            receiveFiles();
        }
        catch (std::runtime_error& e){
            std::cerr << "Failure while receiving file! Description of error:" << "\n";
            std::cerr << e.what() << "\n";
            return EXIT_ERROR_RECEIVE_FILES;
        }   
    } else {
        try{
            resolveNameToAddress(arguments.hostName,&address);
        }
        catch (std::runtime_error& e){
            std::cerr << "Failure while resolving name to address! Description of error:\n";
            std::cerr << e.what() << "\n";
            return EXIT_ERROR_NAME_RESOLUTION;
        }
        try{
            sendFile(arguments.fileName,&address, address.addressFamily == AF_INET6);
        } catch (std::runtime_error& e){
            std::cerr << "Failure while sending file! Description of error:\n";
            std::cerr << e.what() << std::endl;
            freeAddress(&address);
            return EXIT_ERROR_SEND_FILE;
        }
        freeAddress(&address);
    }
    return EXIT_SUCCESS;
}