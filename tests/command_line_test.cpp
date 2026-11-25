#include "core/command_line.hpp"

#include <iostream>
#include <string>
#include <vector>

namespace {

bool parse(const std::vector<std::string>& arguments,
           ParseResult expected,
           const std::string& label) {
    std::vector<char*> argv;
    argv.reserve(arguments.size());
    for (const auto& argument : arguments) {
        argv.push_back(const_cast<char*>(argument.c_str()));
    }
    CommandLineOptions options;
    std::string error;
    const auto result = parse_command_line(static_cast<int>(argv.size()),
                                           argv.data(), options, error);
    if (result != expected) {
        std::cerr << "[FAIL] " << label << ": " << error << '\n';
        return false;
    }
    std::cout << "[OK] " << label << '\n';
    return true;
}

}

int main() {
    std::cout << "Проверка аргументов командной строки\n";
    int passed = 0;
    constexpr int TOTAL = 15;
    passed += parse({"encryption_rgr"}, ParseResult::Help, "справка без аргументов");
    passed += parse({"encryption_rgr", "--unknown", "--help"},
                    ParseResult::Help, "справка при конфликтующих аргументах");
    passed += parse({"encryption_rgr", "-a", "hill", "-m", "encrypt",
                     "-k", "key.bin", "-i", "-", "-o", "cipher.bin"},
                    ParseResult::Ready, "короткие псевдонимы и стандартный ввод");
    passed += parse({"encryption_rgr", "--algorithm", "elgamal", "--mode",
                     "generate-key", "--write-key"},
                    ParseResult::Ready, "генерация ключей в стандартный вывод");
    passed += parse({"encryption_rgr", "--algorithm=hill", "--mode=encrypt",
                     "--key=key.bin", "--input=-", "--output=result.bin"},
                    ParseResult::Ready, "длинные аргументы GNU с присваиванием значения");
    passed += parse({"encryption_rgr", "--algorithm", "hill"},
                    ParseResult::Error, "отсутствующие обязательные аргументы");
    passed += parse({"encryption_rgr", "--algorithm", "unknown", "--mode", "encrypt",
                     "--key", "key.bin"},
                    ParseResult::Error, "отклонение неизвестного алгоритма");
    passed += parse({"encryption_rgr", "--algorithm", "hill", "--mode", "encrypt",
                     "--key", "-", "--input", "-"},
                    ParseResult::Error, "отклонение конфликтующего стандартного ввода");
    passed += parse({"encryption_rgr", "--menu"}, ParseResult::Ready,
                    "запуск интерактивного меню");
    passed += parse({"encryption_rgr", "--menu", "--algorithm", "hill"},
                    ParseResult::Error, "отклонение сочетания меню с другими флагами");
    passed += parse({"encryption_rgr", "-a", "hill", "-m", "encrypt",
                     "-g", "-s", "key.bin", "-k", "old.bin"},
                    ParseResult::Error, "конфликт чтения и генерации ключа");
    passed += parse({"encryption_rgr", "-a", "hill", "-m", "encrypt",
                     "-g", "-s", "source.bin", "-i", "source.bin", "-o", "out.bin"},
                    ParseResult::Error, "защита исходника от записи ключа");
    passed += parse({"encryption_rgr", "-a", "hill", "-m", "encrypt",
                     "-k", "key.bin", "-i", "source.bin", "-o", "./key.bin"},
                    ParseResult::Error, "защита ключа через эквивалентный путь");
    passed += parse({"encryption_rgr", "-a", "hill", "-m", "encrypt",
                     "-k", "key.bin", "-i", "result.bin.tmp", "-o", "result.bin"},
                    ParseResult::Error, "защита входа от временного файла");
    passed += parse({"encryption_rgr", "-a", "hill", "-m", "encrypt",
                     "-g", "-s", "key.bin", "-i", "source.bin", "-o", "key.bin"},
                    ParseResult::Error, "конфликт нового ключа и результата");
    std::cout << "Пройдено проверок: " << passed << " из " << TOTAL << '\n';
    return passed == TOTAL ? 0 : 1;
}
