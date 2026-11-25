#include "core/cipher_module.hpp"
#include "core/command_line.hpp"
#include "core/password_auth.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <filesystem>
#include <array>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <memory>
#include <string>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#else
#define NOMINMAX
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#endif

namespace {

enum class Cipher {
    Hill,
    ElGamal,
};

struct VectorCleanser {
    std::vector<std::uint8_t>& bytes;
    ~VectorCleanser() {
        if (!bytes.empty()) OPENSSL_cleanse(bytes.data(), bytes.size());
    }
};

struct StringCleanser {
    std::string& text;
    ~StringCleanser() {
        if (!text.empty()) OPENSSL_cleanse(text.data(), text.size());
    }
};

struct FileCloser {
    void operator()(std::FILE* file) const {
        if (file != nullptr) std::fclose(file);
    }
};

using FilePtr = std::unique_ptr<std::FILE, FileCloser>;

struct FileStreamContext {
    std::FILE* input;
    std::FILE* output;
};

int read_stream_callback(void* context, std::uint8_t* buffer,
                         std::size_t capacity, std::size_t* bytes_read) {
    if (context == nullptr || buffer == nullptr || bytes_read == nullptr) return 0;
    auto* stream = static_cast<FileStreamContext*>(context);
    *bytes_read = std::fread(buffer, 1, capacity, stream->input);
    return std::ferror(stream->input) == 0;
}

int write_stream_callback(void* context, const std::uint8_t* buffer,
                          std::size_t size) {
    if (context == nullptr || (buffer == nullptr && size != 0)) return 0;
    auto* stream = static_cast<FileStreamContext*>(context);
    return size == 0 || std::fwrite(buffer, 1, size, stream->output) == size;
}

// Ввод команд и путей.
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

// Чтение и безопасная запись файлов.
bool read_file(const std::string& path, std::vector<std::uint8_t>& data) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }

    data.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    return !file.bad();
}

bool write_file(const std::string& path, const std::uint8_t* data, std::size_t size) {
    const std::filesystem::path destination(path);
    const std::filesystem::path temporary = path + ".tmp";
    {
        std::ofstream file(temporary, std::ios::binary | std::ios::trunc);
        if (!file) return false;
        if (size != 0) {
            file.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
        }
        file.flush();
        if (!file.good()) {
            file.close();
            std::error_code ignored;
            std::filesystem::remove(temporary, ignored);
            return false;
        }
    }
#ifndef _WIN32
    if (chmod(temporary.c_str(), S_IRUSR | S_IWUSR) != 0) {
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        return false;
    }
#endif
#ifdef _WIN32
    if (!MoveFileExW(temporary.c_str(), destination.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        return false;
    }
#else
    if (std::rename(temporary.c_str(), destination.c_str()) != 0) {
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        return false;
    }
#endif
    return true;
}

bool write_text_file(const std::string& path, const std::string& data) {
    return write_file(path, reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
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

bool ask_yes_no(const std::string& question) {
    while (true) {
        std::cout << question << " [Д/н]: ";
        std::string answer;
        if (!std::getline(std::cin, answer)) return false;
        if (answer.empty() || answer == "Д" || answer == "д" ||
            answer == "Да" || answer == "да" || answer == "Y" || answer == "y") {
            return true;
        }
        if (answer == "Н" || answer == "н" || answer == "Нет" || answer == "нет" ||
            answer == "N" || answer == "n") {
            return false;
        }
        std::cout << "Ответьте «Д» или «н».\n";
    }
}

bool prepare_output_file(const std::string& output_path) {
    std::error_code error;
    const std::filesystem::path path(output_path);
    const bool exists = std::filesystem::exists(path, error);
    if (error) {
        std::cout << "Не удалось проверить выходной путь «" << output_path
                  << "»: " << error.message() << ".\n";
        return false;
    }
    if (exists) {
        const bool is_directory = std::filesystem::is_directory(path, error);
        if (error) {
            std::cout << "Не удалось проверить выходной путь «" << output_path
                      << "»: " << error.message() << ".\n";
            return false;
        }
        if (is_directory) {
            std::cout << "Выходной путь указывает на папку, а не на файл.\n";
            return false;
        }
    }
    if (!exists) {
        const auto parent = path.parent_path();
        const bool parent_exists = parent.empty() || std::filesystem::exists(parent, error);
        if (error) {
            std::cout << "Не удалось проверить папку выходного файла: " << error.message() << ".\n";
            return false;
        }
        std::string question = "Выходной файл «" + output_path + "» не существует. Создать его";
        if (!parent_exists) question += " и необходимые папки";
        question += "?";
        if (!ask_yes_no(question)) {
            std::cout << "Создание выходного файла отменено.\n";
            return false;
        }
    }

    if (!prepare_output_directory(output_path)) return false;
    return true;
}

// Преобразование данных для текстового представления.
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

bool transform_data(const CipherModuleApi* api,
                    bool encrypting,
                    const std::vector<std::uint8_t>& key,
                    const std::vector<std::uint8_t>& input,
                    std::vector<std::uint8_t>& output) {
    const int operation = encrypting ? CIPHER_OPERATION_ENCRYPT
                                    : CIPHER_OPERATION_DECRYPT;
    const std::size_t capacity = api->get_output_size(input.size(), operation);
    if (capacity == 0) return false;
    output.resize(capacity);
    MutBuffer output_buffer{output.data(), output.size()};
    const ConstBuffer key_buffer{key.data(), key.size()};
    const ConstBuffer input_buffer{input.data(), input.size()};
    const int succeeded = encrypting
        ? api->encrypt(key_buffer, input_buffer, &output_buffer)
        : api->decrypt(key_buffer, input_buffer, &output_buffer);
    if (succeeded == 0 || output_buffer.size > output.size()) {
        output.clear();
        return false;
    }
    output.resize(output_buffer.size);
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

// Создание и загрузка ключей алгоритма.
bool save_generated_key(const std::filesystem::path& path,
                        const std::uint8_t* key,
                        std::size_t key_size) {
    std::error_code error;
    std::filesystem::create_directories(path.parent_path(), error);
    if (error || !write_file(path.string(), key, key_size)) return false;
#ifndef _WIN32
    if (chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0) {
        std::filesystem::remove(path, error);
        return false;
    }
#endif
    return true;
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
    api->free_buffer(encryption_key, encryption_key_size);
    api->free_buffer(decryption_key, decryption_key_size);

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

// Шифрование и расшифрование текста.
void encrypt_text(const CipherModule& module, const std::string& key_path) {
    const CipherModuleApi* api = module.api();
    std::vector<std::uint8_t> key;
    VectorCleanser key_cleanser{key};
    if (!load_key(key_path, key)) {
        return;
    }

    std::cout << "Введите текст для шифрования: ";
    std::string text;
    StringCleanser text_cleanser{text};
    if (!std::getline(std::cin, text)) {
        return;
    }

    std::vector<std::uint8_t> plaintext(text.begin(), text.end());
    VectorCleanser plaintext_cleanser{plaintext};
    std::vector<std::uint8_t> output;
    VectorCleanser output_cleanser{output};
    if (!transform_data(api, true, key, plaintext, output)) {
        std::cout << "Не удалось зашифровать текст.\n";
        return;
    }
    std::cout << "Результат в шестнадцатеричном виде:\n"
              << bytes_to_hex(output.data(), output.size()) << '\n';
}

void decrypt_text(const CipherModule& module, const std::string& key_path) {
    const CipherModuleApi* api = module.api();
    std::vector<std::uint8_t> key;
    VectorCleanser key_cleanser{key};
    if (!load_key(key_path, key)) {
        return;
    }

    std::cout << "Введите результат шифрования в шестнадцатеричном виде: ";
    std::string text;
    StringCleanser text_cleanser{text};
    std::vector<std::uint8_t> ciphertext;
    VectorCleanser ciphertext_cleanser{ciphertext};
    if (!std::getline(std::cin, text) || !hex_to_bytes(text, ciphertext)) {
        std::cout << "Неверный формат шестнадцатеричных данных.\n";
        return;
    }

    std::vector<std::uint8_t> output;
    VectorCleanser output_cleanser{output};
    if (!transform_data(api, false, key, ciphertext, output)) {
        std::cout << "Не удалось расшифровать текст. Проверьте ключ и данные.\n";
        return;
    }
    std::cout << "Расшифрованный текст:\n";
    if (!output.empty()) {
        std::cout.write(reinterpret_cast<const char*>(output.data()),
                        static_cast<std::streamsize>(output.size()));
    }
    std::cout << '\n';
}

// Шифрование и расшифрование файлов.
void encrypt_file(const CipherModule& module, const std::string& key_path) {
    const CipherModuleApi* api = module.api();
    std::vector<std::uint8_t> key;
    std::vector<std::uint8_t> input;
    VectorCleanser key_cleanser{key};
    VectorCleanser input_cleanser{input};
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

    std::vector<std::uint8_t> ciphertext;
    VectorCleanser ciphertext_cleanser{ciphertext};
    std::cout << "Выполняется шифрование файла.\n";
    if (!transform_data(api, true, key, input, ciphertext)) {
        std::cout << "Не удалось зашифровать файл.\n";
        return;
    }

    const std::string encoded = bytes_to_hex(ciphertext.data(), ciphertext.size());
    if (!prepare_output_file(output_path)) {
        return;
    }
    const bool saved = write_text_file(output_path, encoded);
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
    VectorCleanser key_cleanser{key};
    VectorCleanser encoded_cleanser{encoded};
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
    VectorCleanser ciphertext_cleanser{ciphertext};
    if (!hex_to_bytes(encoded_text, ciphertext)) {
        std::cout << "Файл не содержит корректные шестнадцатеричные данные.\n";
        return;
    }

    std::vector<std::uint8_t> plaintext;
    VectorCleanser plaintext_cleanser{plaintext};
    std::cout << "Выполняется расшифрование файла.\n";
    if (!transform_data(api, false, key, ciphertext, plaintext)) {
        std::cout << "Не удалось расшифровать файл. Проверьте ключ и данные.\n";
        return;
    }

    if (!prepare_output_file(output_path)) {
        return;
    }
    const bool saved = write_file(output_path, plaintext.data(), plaintext.size());
    if (!saved) {
        std::cout << "Не удалось записать файл «" << output_path << "». Проверьте путь и права доступа.\n";
        return;
    }
    std::cout << "Готово. Расшифрованный текст записан в «" << output_path << "».\n";
}

// Выбор и загрузка динамической библиотеки.
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

struct OwnedModuleBuffer {
    const CipherModuleApi* api = nullptr;
    std::uint8_t* data = nullptr;
    std::size_t size = 0;

    ~OwnedModuleBuffer() {
        if (api != nullptr && data != nullptr) api->free_buffer(data, size);
    }
};

constexpr std::array<std::uint8_t, 8> kKeyPairMagic{
    'C', 'R', 'Y', 'P', 'K', 'E', 'Y', '1'};

void append_u64(std::vector<std::uint8_t>& output, std::uint64_t value) {
    for (std::size_t index = 0; index < sizeof(value); ++index) {
        output.push_back(static_cast<std::uint8_t>(value >> (index * 8)));
    }
}

bool read_u64(const std::vector<std::uint8_t>& input,
              std::size_t offset,
              std::uint64_t& value) {
    if (offset > input.size() || input.size() - offset < sizeof(value)) return false;
    value = 0;
    for (std::size_t index = 0; index < sizeof(value); ++index) {
        value |= static_cast<std::uint64_t>(input[offset + index]) << (index * 8);
    }
    return true;
}

bool generate_key_pair(const CipherModule& module,
                       std::vector<std::uint8_t>& encryption_key,
                       std::vector<std::uint8_t>& decryption_key) {
    const auto* api = module.api();
    OwnedModuleBuffer encryption{api};
    OwnedModuleBuffer decryption{api};
    std::size_t encryption_size = 0;
    std::size_t decryption_size = 0;
    if (api->generate_keys(nullptr, 0, &encryption.data, &encryption_size,
                           &decryption.data, &decryption_size) == 0 ||
        encryption.data == nullptr || decryption.data == nullptr ||
        encryption_size == 0 || decryption_size == 0) {
        return false;
    }
    encryption.size = encryption_size;
    decryption.size = decryption_size;
    encryption_key.assign(encryption.data, encryption.data + encryption_size);
    decryption_key.assign(decryption.data, decryption.data + decryption_size);
    return true;
}

std::vector<std::uint8_t> make_key_pair_record(
    const std::vector<std::uint8_t>& encryption_key,
    const std::vector<std::uint8_t>& decryption_key) {
    std::vector<std::uint8_t> record(kKeyPairMagic.begin(), kKeyPairMagic.end());
    append_u64(record, encryption_key.size());
    append_u64(record, decryption_key.size());
    record.insert(record.end(), encryption_key.begin(), encryption_key.end());
    record.insert(record.end(), decryption_key.begin(), decryption_key.end());
    return record;
}

bool select_key(const std::vector<std::uint8_t>& record,
                OperationMode mode,
                std::vector<std::uint8_t>& key) {
    if (record.size() < kKeyPairMagic.size() + 2 * sizeof(std::uint64_t) ||
        !std::equal(kKeyPairMagic.begin(), kKeyPairMagic.end(), record.begin())) {
        key = record;
        return !key.empty();
    }
    std::uint64_t encryption_size = 0;
    std::uint64_t decryption_size = 0;
    constexpr std::size_t lengths_offset = kKeyPairMagic.size();
    constexpr std::size_t data_offset = lengths_offset + 2 * sizeof(std::uint64_t);
    if (!read_u64(record, lengths_offset, encryption_size) ||
        !read_u64(record, lengths_offset + sizeof(std::uint64_t), decryption_size) ||
        encryption_size > record.size() - data_offset ||
        decryption_size != record.size() - data_offset - encryption_size) {
        return false;
    }
    const std::size_t selected_offset = mode == OperationMode::Encrypt
        ? data_offset
        : data_offset + static_cast<std::size_t>(encryption_size);
    const std::size_t selected_size = static_cast<std::size_t>(
        mode == OperationMode::Encrypt ? encryption_size : decryption_size);
    if (selected_size == 0) return false;
    key.assign(record.begin() + static_cast<std::ptrdiff_t>(selected_offset),
               record.begin() + static_cast<std::ptrdiff_t>(selected_offset + selected_size));
    return true;
}

bool spool_input(FILE* source, FILE* spool, std::uint64_t& size,
                 std::array<std::uint8_t, 32>& digest) {
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> digest_context(
        EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!digest_context || EVP_DigestInit_ex(digest_context.get(), EVP_sha256(), nullptr) != 1) {
        return false;
    }
    std::array<std::uint8_t, 65536> buffer{};
    size = 0;
    while (true) {
        const std::size_t count = std::fread(buffer.data(), 1, buffer.size(), source);
        if (count != 0) {
            if (size > std::numeric_limits<std::uint64_t>::max() - count ||
                EVP_DigestUpdate(digest_context.get(), buffer.data(), count) != 1 ||
                std::fwrite(buffer.data(), 1, count, spool) != count) {
                OPENSSL_cleanse(buffer.data(), buffer.size());
                return false;
            }
            size += count;
        }
        if (count < buffer.size()) {
            if (std::ferror(source) != 0) {
                OPENSSL_cleanse(buffer.data(), buffer.size());
                return false;
            }
            break;
        }
    }
    OPENSSL_cleanse(buffer.data(), buffer.size());
    unsigned int digest_size = 0;
    return EVP_DigestFinal_ex(digest_context.get(), digest.data(), &digest_size) == 1 &&
           digest_size == digest.size() && std::fflush(spool) == 0 &&
           std::fseek(spool, 0, SEEK_SET) == 0;
}

bool copy_file_stream(FILE* source, FILE* destination) {
    if (std::fseek(source, 0, SEEK_SET) != 0) return false;
    std::array<std::uint8_t, 65536> buffer{};
    while (true) {
        const std::size_t count = std::fread(buffer.data(), 1, buffer.size(), source);
        if (count != 0 && std::fwrite(buffer.data(), 1, count, destination) != count) {
            OPENSSL_cleanse(buffer.data(), buffer.size());
            return false;
        }
        if (count < buffer.size()) {
            const bool success = std::ferror(source) == 0;
            OPENSSL_cleanse(buffer.data(), buffer.size());
            return success;
        }
    }
}

bool commit_cli_output(const std::string& path, FILE* spool) {
    if (path == "-") return copy_file_stream(spool, stdout) && std::fflush(stdout) == 0;
    if (!prepare_output_directory(path)) return false;
    const std::filesystem::path destination(path);
    const std::filesystem::path temporary = path + ".tmp";
    FilePtr output(std::fopen(temporary.string().c_str(), "wb"));
    if (!output || !copy_file_stream(spool, output.get()) || std::fflush(output.get()) != 0) {
        output.reset();
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        return false;
    }
    output.reset();
#ifndef _WIN32
    if (chmod(temporary.c_str(), S_IRUSR | S_IWUSR) != 0) {
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        return false;
    }
#endif
#ifdef _WIN32
    if (!MoveFileExW(temporary.c_str(), destination.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        return false;
    }
#else
    if (std::rename(temporary.c_str(), destination.c_str()) != 0) {
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        return false;
    }
#endif
    return true;
}

bool write_cli_bytes(const std::string& path,
                     const std::uint8_t* data,
                     std::size_t size) {
    if (path == "-") {
        return (size == 0 || std::fwrite(data, 1, size, stdout) == size) &&
               std::fflush(stdout) == 0;
    }
    if (!prepare_output_directory(path)) return false;
    return write_file(path, data, size);
}

int execute_cli(const CommandLineOptions& options, const char* executable_path) {
    const Cipher cipher = options.algorithm == "hill" ? Cipher::Hill : Cipher::ElGamal;
    CipherModule module;
    std::string error;
    if (!module.load(module_path(cipher, executable_path).string(), error)) {
        std::cerr << "Не удалось загрузить модуль алгоритма: " << error << '\n';
        return 1;
    }

    std::vector<std::uint8_t> encryption_key;
    std::vector<std::uint8_t> decryption_key;
    VectorCleanser encryption_key_cleanser{encryption_key};
    VectorCleanser decryption_key_cleanser{decryption_key};
    if (options.mode == OperationMode::GenerateKey || options.generate_key) {
        if (!generate_key_pair(module, encryption_key, decryption_key)) {
            std::cerr << "Не удалось сгенерировать ключи.\n";
            return 1;
        }
        auto key_record = make_key_pair_record(encryption_key, decryption_key);
        VectorCleanser key_record_cleanser{key_record};
        if (options.write_key) {
            if (!write_cli_bytes("-", key_record.data(), key_record.size())) {
                std::cerr << "Не удалось вывести ключи в стандартный поток.\n";
                return 1;
            }
            return 0;
        }
        if (options.save_key_path.empty() ||
            !write_cli_bytes(options.save_key_path, key_record.data(), key_record.size())) {
            std::cerr << "Не удалось сохранить пару ключей.\n";
            return 1;
        }
        if (options.mode == OperationMode::GenerateKey) return 0;
    } else {
        std::vector<std::uint8_t> key_record;
        VectorCleanser key_record_cleanser{key_record};
        const bool key_read = options.key_path == "-"
            ? (key_record.assign(std::istreambuf_iterator<char>(std::cin),
                                 std::istreambuf_iterator<char>()), !std::cin.bad())
            : read_file(options.key_path, key_record);
        if (!key_read ||
            !select_key(key_record, options.mode, encryption_key)) {
            std::cerr << "Не удалось прочитать ключ из «" << options.key_path << "».\n";
            return 1;
        }
    }

    const auto* api = module.api();
    FilePtr input_file(options.input_path == "-"
        ? nullptr : std::fopen(options.input_path.c_str(), "rb"));
    FILE* input_handle = options.input_path == "-" ? stdin : input_file.get();
    FilePtr input_spool(std::tmpfile());
    FilePtr output_spool(std::tmpfile());
    if (input_handle == nullptr || !input_spool || !output_spool) {
        std::cerr << "Не удалось открыть входной или временный файл.\n";
        return 1;
    }
    std::uint64_t input_size = 0;
    std::array<std::uint8_t, 32> input_digest{};
    if (options.mode == OperationMode::Encrypt &&
        !spool_input(input_handle, input_spool.get(), input_size, input_digest)) {
        std::cerr << "Не удалось подготовить входные данные для шифрования.\n";
        return 1;
    }
    FILE* transform_input = options.mode == OperationMode::Encrypt
        ? input_spool.get() : input_handle;
    FileStreamContext transform_context{transform_input, output_spool.get()};
    const ConstBuffer key_buffer{encryption_key.data(), encryption_key.size()};
    const bool transformed = options.mode == OperationMode::Encrypt
        ? api->encrypt_stream(key_buffer, input_size, input_digest.data(),
                              read_stream_callback, write_stream_callback,
                              &transform_context) != 0
        : api->decrypt_stream(key_buffer, read_stream_callback,
                              write_stream_callback, &transform_context) != 0;
    if (!transformed) {
        std::cerr << (options.mode == OperationMode::Encrypt
            ? "Не удалось зашифровать входные данные.\n"
            : "Не удалось расшифровать входные данные. Проверьте ключ и контейнер.\n");
        return 1;
    }
    if (std::fflush(output_spool.get()) != 0 ||
        !commit_cli_output(options.output_path, output_spool.get())) {
        std::cerr << "Не удалось записать результат.\n";
        return 1;
    }
    return 0;
}

// Меню выбранного алгоритма.
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

// Главное меню приложения.
int main(int argc, char* argv[]) {
#ifdef _WIN32
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
#endif
    const char* executable_path = argc > 0 ? argv[0] : "encryption_rgr";
    CommandLineOptions options;
    std::string error;
    const ParseResult result = parse_command_line(argc, argv, options, error);
    if (result == ParseResult::Help) {
        std::cout << command_line_help(executable_path);
        return 0;
    }
    if (result == ParseResult::Error) {
        std::cerr << error << '\n' << command_line_help(executable_path);
        return 2;
    }
#ifdef _WIN32
    if (!options.menu) {
        _setmode(_fileno(stdin), _O_BINARY);
        _setmode(_fileno(stdout), _O_BINARY);
    }
#endif
    if (!authenticate_user()) {
        std::cerr << "Доступ к программе закрыт.\n";
        return 1;
    }
    if (options.menu) {
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
            } catch (const std::exception& exception) {
                std::cerr << "Операция прервана из-за ошибки: " << exception.what() << '\n';
            }
        }
    }
    try {
        return execute_cli(options, executable_path);
    } catch (const std::exception& exception) {
        std::cerr << "Операция прервана из-за ошибки: " << exception.what() << '\n';
        return 1;
    } catch (...) {
        std::cerr << "Операция прервана из-за неизвестной ошибки.\n";
        return 1;
    }
}
