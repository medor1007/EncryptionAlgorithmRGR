#include "core/command_line.hpp"

#include <unordered_map>
#include <filesystem>
#include <utility>
#include <vector>

namespace {

const std::unordered_map<std::string, std::string> ALIASES{
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

}

// Запрещаем совпадение исходных данных, результата, ключей и временных файлов.
bool validate_file_paths(const CommandLineOptions& options, std::string& error) {
    const auto same_file = [](const std::string& first, const std::string& second) {
        std::error_code filesystem_error;
        if (std::filesystem::equivalent(first, second, filesystem_error) &&
            !filesystem_error) return true;
        filesystem_error.clear();
        const auto first_absolute = std::filesystem::absolute(first, filesystem_error);
        if (filesystem_error) return false;
        const auto first_path = std::filesystem::weakly_canonical(first_absolute, filesystem_error);
        if (filesystem_error) return false;
        const auto second_absolute = std::filesystem::absolute(second, filesystem_error);
        if (filesystem_error) return false;
        const auto second_path = std::filesystem::weakly_canonical(second_absolute, filesystem_error);
        return !filesystem_error && first_path == second_path;
    };
    const std::vector<std::pair<std::string, std::string>> paths{
        {"входных данных", options.mode == OperationMode::GenerateKey ? "" : options.input_path},
        {"результата", options.mode == OperationMode::GenerateKey ? "" : options.output_path},
        {"ключа", options.key_path},
        {"новой пары ключей", options.save_key_path},
    };
    for (std::size_t first = 0; first < paths.size(); ++first) {
        if (paths[first].second.empty() || paths[first].second == "-") continue;
        for (std::size_t second = first + 1; second < paths.size(); ++second) {
            if (paths[second].second.empty() || paths[second].second == "-") continue;
            if (same_file(paths[first].second, paths[second].second)) {
                error = "Пути " + paths[first].first + " и " + paths[second].first +
                        " указывают на один файл.";
                return false;
            }
        }
    }
    for (const auto& output : {options.save_key_path,
                              options.mode == OperationMode::GenerateKey ? "" : options.output_path}) {
        if (output.empty() || output == "-") continue;
        for (const auto& input : paths) {
            if (input.second.empty() || input.second == "-") continue;
            if (same_file(output + ".tmp", input.second)) {
                error = "Временный файл результата совпадает с используемым файлом.";
                return false;
            }
        }
    }
    return true;
}

// Разбор коротких и длинных аргументов и проверка их сочетаний.
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
        const auto alias = ALIASES.find(option);
        if (alias != ALIASES.end()) {
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
            error = "Аргумент --menu нельзя сочетать с другими параметрами.";
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

    if (options.generate_key && !options.key_path.empty()) {
        error = "Нельзя одновременно указывать --key и --generate-key.";
        return ParseResult::Error;
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
    return validate_file_paths(options, error) ? ParseResult::Ready : ParseResult::Error;
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
           "  -w, --write-key            вывести пару ключей в стандартный поток\n"
           "  -u, --menu                 открыть интерактивное меню\n\n"
           "Примеры:\n"
           "  " + program + " -a hill -m generate-key -s hill.keys\n"
           "  " + program + " --algorithm elgamal --mode encrypt --key keys.bin "
           "--input report.pdf --output report.pdf.enc\n"
           "  cat report.pdf | " + program + " -a elgamal -m encrypt -k keys.bin > report.enc\n"
           "  " + program + " -a elgamal -m decrypt -k keys.bin -i report.enc -o report.pdf\n";
}
