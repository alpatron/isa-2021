#include "exitCodes.hpp"
#include "argumentParsing.hpp"
#include <iostream>

int main (int argc, char* argv[]){
    Arguments arguments;

    try{
        parseCommandLineArguments(argc,argv,&arguments);
    }
    catch (std::runtime_error& e){
        std::cerr << e.what() << std::endl;
        return EXIT_ERROR_COMMAND_LINE_ARGUMENT;
    }

    std::cout << "All is well!\n";
    std::cout << "Mode:" << (arguments.listeningMode ? "receiver" : "sender") << "\n";
    if (!arguments.listeningMode){
        std::cout << "File name:" << arguments.fileName << "\n";
        std::cout << "Host name:" << arguments.hostName << "\n";
    }
    return EXIT_SUCCESS;
}