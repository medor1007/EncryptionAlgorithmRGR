#ifndef COMMAND_LINE_HPP
#define COMMAND_LINE_HPP

#include <string>
#include <vector>

enum class OperationMode {
    Encrypt,
    Decrypt,
    GenerateKey,
};

struct CommandLineOptions {
    bool help = false;
    std::string algorithm;
    OperationMode mode = OperationMode::Encrypt;
    bool mode_set = false;
    std::string key_path;
    std::string input_path = "-";
    std::string output_path = "-";
    bool generate_key = false;
    std::string save_key_path;
    bool write_key = false;
};

enum class ParseResult {
    Help,
    Ready,
    Error,
};

ParseResult parse_command_line(int argc,
                               char* argv[],
                               CommandLineOptions& options,
                               std::string& error);

std::string command_line_help(const char* executable_name);

#endif
