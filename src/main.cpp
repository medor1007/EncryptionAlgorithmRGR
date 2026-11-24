#include "core/cipher_module.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

namespace {

enum class Cipher {
    Hill,
    ElGamal,
};

int read_choice(int minimum, int maximum) {
    while (true) {
        std::cout << "Выберите пункт: ";
        std::string input;
        if (!std::getline(std::cin, input)) {
            return 0;
        }

        try {
            std::size_t parsed = 0;
            const int choice = std::stoi(input, &parsed);
            if (parsed == input.size() && choice >= minimum && choice <= maximum) {
                return choice;
            }
        } catch (const std::exception&) {
            // Некорректный ввод обработается общим сообщением ниже.
        }

        std::cout << "Некорректный ввод. Введите число от " << minimum
                  << " до " << maximum << ".\n";
    }
}

std::string prompt_path(const std::string& message, const std::string& default_path) {
    std::cout << message << " [" << default_path << "]: ";
    std::string path;
    if (!std::getline(std::cin, path) || path.empty()) {
        return default_path;
    }
    return path;
}

bool read_file(const std::string& path, std::vector<std::uint8_t>& data) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }

    data.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    return !file.bad();
}

bool write_file(const std::string& path, const std::uint8_t* data, std::size_t size) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) {
        return false;
    }
    if (size != 0) {
        file.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
    }
    return file.good();
}

bool write_text_file(const std::string& path, const std::string& data) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) {
        return false;
    }
    file.write(data.data(), static_cast<std::streamsize>(data.size()));
    return file.good();
}

bool wait_for_enter(const std::string& instruction) {
    std::cout << instruction << '\n';
    std::string line;
    return static_cast<bool>(std::getline(std::cin, line));
}

bool same_path(const std::string& first, const std::string& second) {
    std::error_code error;
    const auto absolute_first = std::filesystem::absolute(first, error);
    if (error) {
        return std::filesystem::path(first).lexically_normal() ==
               std::filesystem::path(second).lexically_normal();
    }
    const auto absolute_second = std::filesystem::absolute(second, error);
    if (error) {
        return std::filesystem::path(first).lexically_normal() ==
               std::filesystem::path(second).lexically_normal();
    }
    return absolute_first.lexically_normal() == absolute_second.lexically_normal();
}

bool prepare_output_directory(const std::string& output_path) {
    const std::filesystem::path parent = std::filesystem::path(output_path).parent_path();
    if (parent.empty()) {
        return true;
    }
    std::error_code error;
    std::filesystem::create_directories(parent, error);
    if (error) {
        std::cout << "Не удалось создать папку для файла «" << output_path
                  << "»: " << error.message() << ".\n";
        return false;
    }
    return true;
}

std::string bytes_to_hex(const std::uint8_t* data, std::size_t size) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string result;
    result.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) {
        result.push_back(digits[data[i] >> 4]);
        result.push_back(digits[data[i] & 0x0f]);
    }
    return result;
}

int hex_value(char symbol) {
    if (symbol >= '0' && symbol <= '9') return symbol - '0';
    if (symbol >= 'A' && symbol <= 'F') return symbol - 'A' + 10;
    if (symbol >= 'a' && symbol <= 'f') return symbol - 'a' + 10;
    return -1;
}

bool hex_to_bytes(const std::string& text, std::vector<std::uint8_t>& data) {
    std::string compact;
    compact.reserve(text.size());
    for (unsigned char symbol : text) {
        if (symbol == ' ' || symbol == '\n' || symbol == '\r' || symbol == '\t') {
            continue;
        }
        compact.push_back(static_cast<char>(symbol));
    }
    if (compact.size() % 2 != 0) {
        return false;
    }

    data.clear();
    data.reserve(compact.size() / 2);
    for (std::size_t i = 0; i < compact.size(); i += 2) {
        const int high = hex_value(compact[i]);
        const int low = hex_value(compact[i + 1]);
        if (high < 0 || low < 0) {
            data.clear();
            return false;
        }
        data.push_back(static_cast<std::uint8_t>((high << 4) | low));
    }
    return true;
}

bool load_key(const std::string& path, std::vector<std::uint8_t>& key) {
    if (!read_file(path, key) || key.empty()) {
        std::cout << "Не удалось прочитать ключ «" << path
                  << R"(». Проверьте путь к файлу ключа.)" << '\n';
        return false;
    }
    return true;
}

bool save_generated_key(const std::filesystem::path& path,
                        const std::uint8_t* key,
                        std::size_t key_size) {
    std::error_code error;
    std::filesystem::create_directories(path.parent_path(), error);
    return !error && write_file(path.string(), key, key_size);
}

bool generate_keys(const CipherModule& module, const std::string& key_prefix) {
    const CipherModuleApi* api = module.api();
    std::uint8_t* encryption_key = nullptr;
    std::uint8_t* decryption_key = nullptr;
    std::size_t encryption_key_size = 0;
    std::size_t decryption_key_size = 0;

    if (api->generate_keys(nullptr, 0, &encryption_key, &encryption_key_size,
                           &decryption_key, &decryption_key_size) == 0) {
        std::cout << "Не удалось сгенерировать ключи.\n";
        return false;
    }

    const std::filesystem::path encryption_path = key_prefix + "_encryption.key";
    const std::filesystem::path decryption_path = key_prefix + "_decryption.key";
    const bool saved = save_generated_key(encryption_path, encryption_key, encryption_key_size) &&
                       save_generated_key(decryption_path, decryption_key, decryption_key_size);
    api->free_buffer(encryption_key);
    api->free_buffer(decryption_key);

    if (!saved) {
        std::cout << "Не удалось сохранить файлы ключей.\n";
        return false;
    }

    std::cout << "Ключи сохранены в файлы «" << encryption_path.string()
              << "» и «" << decryption_path.string() << "».\n";
    return true;
}

bool prepare_keys(const CipherModule& module, const std::string& key_prefix) {
    const std::filesystem::path encryption_path = key_prefix + "_encryption.key";
    const std::filesystem::path decryption_path = key_prefix + "_decryption.key";
    std::error_code error;
    std::filesystem::create_directories(encryption_path.parent_path(), error);
    if (error) {
        std::cout << "Не удалось создать каталог для ключей.\n";
        return false;
    }
    const auto key_exists = [&error](const std::filesystem::path& path, bool& exists) {
        error.clear();
        exists = std::filesystem::is_regular_file(path, error);
        if (error == std::errc::no_such_file_or_directory) {
            error.clear();
            exists = false;
        }
        return !error;
    };
    bool encryption_exists = false;
    bool decryption_exists = false;
    if (!key_exists(encryption_path, encryption_exists) ||
        !key_exists(decryption_path, decryption_exists)) {
        std::cout << "Не удалось проверить файлы ключей.\n";
        return false;
    }
    if (encryption_exists && decryption_exists) {
        return true;
    }

    if (encryption_exists || decryption_exists) {
        std::cout << "Обнаружен только один ключ из пары. Будет создана новая пара; "
                     "старые зашифрованные данные могут перестать расшифровываться.\n";
    } else {
        std::cout << "Ключи ещё не созданы. Подготавливаю их автоматически.\n";
    }
    return generate_keys(module, key_prefix);
}

void encrypt_text(const CipherModule& module, const std::string& key_path) {
    const CipherModuleApi* api = module.api();
    std::vector<std::uint8_t> key;
    if (!load_key(key_path, key)) {
        return;
    }

    std::cout << "Введите текст для шифрования: ";
    std::string text;
    if (!std::getline(std::cin, text)) {
        return;
    }

    std::uint8_t* output = nullptr;
    std::size_t output_size = 0;
    if (api->encrypt(key.data(), key.size(),
                     reinterpret_cast<const std::uint8_t*>(text.data()), text.size(),
                     &output, &output_size) == 0) {
        std::cout << "Не удалось зашифровать текст.\n";
        return;
    }
    std::cout << "Результат в шестнадцатеричном виде:\n"
              << bytes_to_hex(output, output_size) << '\n';
    api->free_buffer(output);
}

void decrypt_text(const CipherModule& module, const std::string& key_path) {
    const CipherModuleApi* api = module.api();
    std::vector<std::uint8_t> key;
    if (!load_key(key_path, key)) {
        return;
    }

    std::cout << "Введите результат шифрования в шестнадцатеричном виде: ";
    std::string text;
    std::vector<std::uint8_t> ciphertext;
    if (!std::getline(std::cin, text) || !hex_to_bytes(text, ciphertext)) {
        std::cout << "Неверный формат шестнадцатеричных данных.\n";
        return;
    }

    std::uint8_t* output = nullptr;
    std::size_t output_size = 0;
    if (api->decrypt(key.data(), key.size(), ciphertext.data(), ciphertext.size(),
                     &output, &output_size) == 0) {
        std::cout << "Не удалось расшифровать текст. Проверьте ключ и данные.\n";
        return;
    }
    std::cout << "Расшифрованный текст:\n";
    if (output_size != 0) {
        std::cout.write(reinterpret_cast<const char*>(output),
                        static_cast<std::streamsize>(output_size));
    }
    std::cout << '\n';
    api->free_buffer(output);
}

void encrypt_file(const CipherModule& module, const std::string& key_path) {
    const CipherModuleApi* api = module.api();
    std::vector<std::uint8_t> key;
    std::vector<std::uint8_t> input;
    if (!load_key(key_path, key)) {
        return;
    }

    const std::string input_path = prompt_path("Путь к файлу с исходными данными", "input.txt");
    const std::string output_path = prompt_path("Путь к файлу с результатом", "encrypted.txt");
    if (same_path(input_path, output_path)) {
        std::cout << "Входной и выходной файлы должны иметь разные пути.\n";
        return;
    }
    if (!wait_for_enter("Запишите исходные данные в файл «" + input_path + "» и сохраните его.")) {
        return;
    }
    if (!read_file(input_path, input)) {
        std::cout << "Не удалось прочитать файл «" << input_path << "». Проверьте путь и права доступа.\n";
        return;
    }

    std::uint8_t* ciphertext = nullptr;
    std::size_t ciphertext_size = 0;
    if (api->encrypt(key.data(), key.size(), input.data(), input.size(),
                     &ciphertext, &ciphertext_size) == 0) {
        std::cout << "Не удалось зашифровать файл.\n";
        return;
    }

    const std::string encoded = bytes_to_hex(ciphertext, ciphertext_size);
    if (!prepare_output_directory(output_path)) {
        api->free_buffer(ciphertext);
        return;
    }
    const bool saved = write_text_file(output_path, encoded);
    api->free_buffer(ciphertext);
    if (!saved) {
        std::cout << "Не удалось записать файл «" << output_path << "». Проверьте путь и права доступа.\n";
        return;
    }
    std::cout << "Готово. Зашифрованный текст записан в «" << output_path << "».\n";
}

void decrypt_file(const CipherModule& module, const std::string& key_path) {
    const CipherModuleApi* api = module.api();
    std::vector<std::uint8_t> key;
    std::vector<std::uint8_t> encoded;
    if (!load_key(key_path, key)) {
        return;
    }

    const std::string input_path = prompt_path("Путь к файлу с шифротекстом", "encrypted.txt");
    const std::string output_path = prompt_path("Путь к файлу с результатом", "decrypted.txt");
    if (same_path(input_path, output_path)) {
        std::cout << "Входной и выходной файлы должны иметь разные пути.\n";
        return;
    }
    if (!wait_for_enter("Скопируйте шифротекст в файл «" + input_path + "» и сохраните его.")) {
        return;
    }
    if (!read_file(input_path, encoded)) {
        std::cout << "Не удалось прочитать файл «" << input_path << "». Проверьте путь и права доступа.\n";
        return;
    }

    const std::string encoded_text(encoded.begin(), encoded.end());
    std::vector<std::uint8_t> ciphertext;
    if (!hex_to_bytes(encoded_text, ciphertext)) {
        std::cout << "Файл не содержит корректные шестнадцатеричные данные.\n";
        return;
    }

    std::uint8_t* plaintext = nullptr;
    std::size_t plaintext_size = 0;
    if (api->decrypt(key.data(), key.size(), ciphertext.data(), ciphertext.size(),
                     &plaintext, &plaintext_size) == 0) {
        std::cout << "Не удалось расшифровать файл. Проверьте ключ и данные.\n";
        return;
    }

    if (!prepare_output_directory(output_path)) {
        api->free_buffer(plaintext);
        return;
    }
    const bool saved = write_file(output_path, plaintext, plaintext_size);
    api->free_buffer(plaintext);
    if (!saved) {
        std::cout << "Не удалось записать файл «" << output_path << "». Проверьте путь и права доступа.\n";
        return;
    }
    std::cout << "Готово. Расшифрованный текст записан в «" << output_path << "».\n";
}

std::filesystem::path module_path(Cipher cipher, const char* executable_path) {
    std::filesystem::path executable(executable_path);
    std::filesystem::path directory = executable.has_parent_path()
        ? executable.parent_path()
        : std::filesystem::current_path();
#ifdef _WIN32
    const char* filename = cipher == Cipher::Hill ? "cipher_hill.dll" : "cipher_elgamal.dll";
#elif __APPLE__
    const char* filename = cipher == Cipher::Hill ? "libcipher_hill.dylib" : "libcipher_elgamal.dylib";
#else
    const char* filename = cipher == Cipher::Hill ? "libcipher_hill.so" : "libcipher_elgamal.so";
#endif
    return directory / "modules" / filename;
}

std::string key_prefix(Cipher cipher) {
    return cipher == Cipher::Hill ? "keys/hill" : "keys/elgamal";
}

void show_cipher_menu(Cipher cipher, const char* executable_path) {
    const auto path = module_path(cipher, executable_path);
    CipherModule module;
    std::string error;
    if (!module.load(path.string(), error)) {
        std::cout << "Не удалось открыть модуль шифра: " << error << '\n';
        return;
    }

    const std::string prefix = key_prefix(cipher);
    if (!prepare_keys(module, prefix)) {
        return;
    }

    std::cout << "Ключи готовы. При первом запуске они создаются автоматически.\n";
    while (true) {
        std::cout << "\n" << module.name() << "\n"
                  << "1. Зашифровать текст из терминала\n"
                  << "2. Расшифровать текст из терминала\n"
                  << "3. Зашифровать файл\n"
                  << "4. Расшифровать файл\n"
                  << "5. Заменить ключи (старые шифротексты не подойдут)\n"
                  << "0. Назад\n";

        const int choice = read_choice(0, 5);
        if (choice == 0) {
            return;
        }
        switch (choice) {
            case 1: {
                const std::string key_path = prompt_path(
                    "Путь к файлу ключа шифрования", prefix + "_encryption.key");
                encrypt_text(module, key_path);
                break;
            }
            case 2: {
                const std::string key_path = prompt_path(
                    "Путь к файлу ключа расшифрования", prefix + "_decryption.key");
                decrypt_text(module, key_path);
                break;
            }
            case 3: {
                const std::string key_path = prompt_path(
                    "Путь к файлу ключа шифрования", prefix + "_encryption.key");
                encrypt_file(module, key_path);
                break;
            }
            case 4: {
                const std::string key_path = prompt_path(
                    "Путь к файлу ключа расшифрования", prefix + "_decryption.key");
                decrypt_file(module, key_path);
                break;
            }
            case 5: {
                std::cout << "Введите ДА, чтобы создать новую пару ключей: ";
                std::string confirmation;
                if (std::getline(std::cin, confirmation) && confirmation == "ДА") {
                    generate_keys(module, prefix);
                } else {
                    std::cout << "Ключи не изменены.\n";
                }
                break;
            }
            default:
                break;
        }
    }
}

}  // Анонимное пространство имён.

int main(int argc, char* argv[]) {
    const char* executable_path = argc > 0 ? argv[0] : "encryption_rgr";
    while (true) {
        std::cout << "\nПрограмма-шифратор и дешифратор\n\n"
                  << "1. Шифр Хилла\n"
                  << "2. Шифр Эль-Гамаля\n"
                  << "0. Выход\n";

        const int choice = read_choice(0, 2);
        if (choice == 0) {
            std::cout << "Вы вышли из программы.\n";
            return 0;
        }
        try {
            show_cipher_menu(choice == 1 ? Cipher::Hill : Cipher::ElGamal,
                             executable_path);
        } catch (const std::exception& error) {
            std::cout << "Операция прервана из-за ошибки: " << error.what()
                      << ". Возврат в главное меню.\n";
        } catch (...) {
            std::cout << "Операция прервана из-за неизвестной ошибки. "
                         "Возврат в главное меню.\n";
        }
    }
}
