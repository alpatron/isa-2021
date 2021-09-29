#ifndef ARGUMENT_PARSING_H
#define ARGUMENT_PARSING_H

/**
 * @brief Structure specifying command-line arguments.
 * 
 */
typedef struct _arguments {
    bool listeningMode;
    char* fileName;
    char* hostName;
} Arguments;

void parseCommandLineArguments(int argc, char* argv[], Arguments* args);

#endif