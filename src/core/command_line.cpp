#include "core/command_line.hpp"

#include <unordered_map>

namespace {

const std::unordered_map<std::string, std::string> kAliases{
    {"-a", "--algorithm"},
    {"-m", "--mode"},
    {"-k", "--key"},
    {"-i", "--input"},
    {"-o", "--output"},
    {"-g", "--generate-key"},
    {"-s", "--save-key"},
    {"-w", "--write-key"},
    {"-u", "--menu"},
    {"-h", "--help"},
};

bool assign_value(int& index,
                  int argc,
                  char* argv[],
                  const std::string& option,
                  std::string& value,
                  std::string& error) {
    if (index + 1 >= argc ||
        (argv[index + 1][0] == '-' && std::string(argv[index + 1]) != "-")) {
        error = "Для аргумента " + option + " требуется значение.";
        return false;
    }
    value = argv[++index];
    return true;
}

}  // namespace

ParseResult parse_command_line(int argc,
                               char* argv[],
                               CommandLineOptions& options,
                               std::string& error) {
    if (argc <= 1) {
        options.help = true;
        return ParseResult::Help;
    }
    for (int index = 1; index < argc; ++index) {
        if (std::string(argv[index]) == "--help" ||
            std::string(argv[index]) == "-h") {
            options.help = true;
            return ParseResult::Help;
        }
    }

    for (int index = 1; index < argc; ++index) {
        std::string option = argv[index];
        std::string inline_value;
        bool has_inline_value = false;
        const std::size_t equals_position = option.find('=');
        if (equals_position != std::string::npos) {
            inline_value = option.substr(equals_position + 1);
            option.erase(equals_position);
            has_inline_value = true;
        }
        if (option == "--help" || option == "-h") continue;
        const auto alias = kAliases.find(option);
        if (alias != kAliases.end()) {
            option = alias->second;
        }

        std::string value;
        const auto read_value = [&](const std::string& name,
                                    std::string& destination) {
            if (has_inline_value) {
                if (inline_value.empty()) {
                    error = "Для аргумента " + name + " требуется непустое значение.";
                    return false;
                }
                destination = inline_value;
                return true;
            }
            return assign_value(index, argc, argv, name, destination, error);
        };
        if (option == "--algorithm") {
            if (!read_value(option, value)) return ParseResult::Error;
            options.algorithm = value;
        } else if (option == "--mode") {
            if (!read_value(option, value)) return ParseResult::Error;
            options.mode_set = true;
            if (value == "encrypt") options.mode = OperationMode::Encrypt;
            else if (value == "decrypt") options.mode = OperationMode::Decrypt;
            else if (value == "generate-key") options.mode = OperationMode::GenerateKey;
            else {
                error = "Неизвестный режим «" + value + "».";
                return ParseResult::Error;
            }
        } else if (option == "--key") {
            if (!read_value(option, value)) return ParseResult::Error;
            options.key_path = value;
        } else if (option == "--input") {
            if (!read_value(option, value)) return ParseResult::Error;
            options.input_path = value;
        } else if (option == "--output") {
            if (!read_value(option, value)) return ParseResult::Error;
            options.output_path = value;
        } else if (option == "--generate-key") {
            options.generate_key = true;
        } else if (option == "--save-key") {
            if (!read_value(option, value)) return ParseResult::Error;
            options.save_key_path = value;
        } else if (option == "--write-key") {
            options.write_key = true;
        } else if (option == "--menu") {
            options.menu = true;
        } else {
            error = "Неизвестный аргумент «" + std::string(argv[index]) + "».";
            return ParseResult::Error;
        }
        if (has_inline_value && option != "--algorithm" && option != "--mode" &&
            option != "--key" && option != "--input" && option != "--output" &&
            option != "--save-key") {
            error = "Аргумент " + option + " не принимает значение.";
            return ParseResult::Error;
        }
    }

    // Справка имеет приоритет над любыми конфликтующими аргументами.
    if (options.help) return ParseResult::Help;
    if (options.menu) {
        if (argc != 2) {
            error = "Флаг --menu нельзя сочетать с другими аргументами.";
            return ParseResult::Error;
        }
        return ParseResult::Ready;
    }
    if (options.algorithm.empty() || !options.mode_set) {
        error = "Необходимо указать алгоритм и режим работы.";
        return ParseResult::Error;
    }
    if (options.algorithm != "hill" && options.algorithm != "elgamal") {
        error = "Неизвестный алгоритм «" + options.algorithm +
                "». Допустимы: hill, elgamal.";
        return ParseResult::Error;
    }

    if (options.mode == OperationMode::GenerateKey) {
        if (options.generate_key || !options.key_path.empty() ||
            options.input_path != "-" || options.output_path != "-" ||
            (options.save_key_path.empty() && !options.write_key) ||
            (!options.save_key_path.empty() && options.write_key)) {
            error = "Для генерации ключей укажите ровно один из аргументов "
                    "--save-key или --write-key; остальные параметры ввода-вывода не нужны.";
            return ParseResult::Error;
        }
        return ParseResult::Ready;
    }

    if (options.write_key) {
        error = "--write-key применяется только вместе с --mode generate-key.";
        return ParseResult::Error;
    }
    if (options.generate_key && options.mode != OperationMode::Encrypt) {
        error = "Автоматическая генерация ключей поддерживается только при шифровании.";
        return ParseResult::Error;
    }
    if (options.generate_key && options.save_key_path.empty()) {
        error = "При --generate-key требуется указать --save-key.";
        return ParseResult::Error;
    }
    if (!options.generate_key && options.key_path.empty()) {
        error = "Для шифрования или расшифрования необходимо указать --key.";
        return ParseResult::Error;
    }
    if (!options.save_key_path.empty() && !options.generate_key) {
        error = "--save-key при шифровании допустим только вместе с --generate-key.";
        return ParseResult::Error;
    }
    if (options.input_path != "-" && options.output_path != "-" &&
        options.input_path == options.output_path) {
        error = "Входной и выходной файлы должны иметь разные пути.";
        return ParseResult::Error;
    }
    if (options.key_path == "-" && options.input_path == "-") {
        error = "Ключ и входные данные не могут одновременно читаться из стандартного ввода.";
        return ParseResult::Error;
    }
    return ParseResult::Ready;
}

std::string command_line_help(const char* executable_name) {
    const std::string program = executable_name == nullptr || executable_name[0] == '\0'
        ? "encryption_rgr"
        : executable_name;
    return "Использование:\n"
           "  " + program + " --help\n"
           "  " + program + " --algorithm NAME --mode MODE [параметры]\n\n"
           "Алгоритмы: hill, elgamal. Режимы: encrypt, decrypt, generate-key.\n\n"
           "Аргументы:\n"
           "  -h, --help                 вывести эту справку\n"
           "  -a, --algorithm NAME       выбрать алгоритм: hill или elgamal\n"
           "  -m, --mode MODE            encrypt, decrypt или generate-key\n"
           "  -k, --key PATH             файл ключевой пары или ключ нужного типа\n"
           "  -i, --input PATH           входной файл; '-' означает стандартный ввод\n"
           "  -o, --output PATH          выходной файл; '-' означает стандартный вывод\n"
           "  -g, --generate-key         создать ключи перед шифрованием\n"
           "  -s, --save-key PATH        сохранить сгенерированную пару ключей\n"
           "  -w, --write-key            вывести пару ключей в стандартный поток\n\n"
           "  -u, --menu                 открыть интерактивное меню\n\n"
           "Примеры:\n"
           "  " + program + " -a hill -m generate-key -s hill.keys\n"
           "  " + program + " --algorithm elgamal --mode encrypt --key keys.bin "
           "--input report.pdf --output report.pdf.enc\n"
           "  cat report.pdf | " + program + " -a elgamal -m encrypt -k keys.bin > report.enc\n"
           "  " + program + " -a elgamal -m decrypt -k keys.bin -i report.enc -o report.pdf\n";
}
