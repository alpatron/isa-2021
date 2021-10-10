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

    
    return EXIT_SUCCESS;
}