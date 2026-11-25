#include "core/cipher_module.hpp"
#include "core/command_line.hpp"
#include "core/password_auth.hpp"
#include "core/secure_memory.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <filesystem>
#include <array>
#include <cstdio>
#include <iostream>
#include <limits>
#include <memory>
#include <string>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
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
    SecureBytes& bytes;
    ~VectorCleanser() {
        if (!bytes.empty()) OPENSSL_cleanse(bytes.data(), bytes.size());
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

bool read_key_stream(FILE* source, SecureBytes& data, std::size_t maximum_size) {
    std::array<std::uint8_t, 4096> buffer{};
    struct BufferWiper {
        std::array<std::uint8_t, 4096>& bytes;
        ~BufferWiper() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
    } wiper{buffer};
    while (true) {
        const std::size_t count = std::fread(buffer.data(), 1, buffer.size(), source);
        if (count > maximum_size - data.size()) return false;
        data.insert(data.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(count));
        if (count < buffer.size()) return std::ferror(source) == 0;
    }
}

bool read_file(const std::string& path, SecureBytes& data, std::size_t maximum_size) {
    FilePtr file(std::fopen(path.c_str(), "rb"));
    if (!file || std::setvbuf(file.get(), nullptr, _IONBF, 0) != 0) return false;
    return read_key_stream(file.get(), data, maximum_size);
}

FilePtr create_private_output(const std::filesystem::path& path) {
#ifndef _WIN32
    const int descriptor = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    if (descriptor < 0) return {};
    FILE* file = fdopen(descriptor, "wb");
    if (file == nullptr) {
        close(descriptor);
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }
#else
    FILE* file = std::fopen(path.string().c_str(), "wbx");
#endif
    if (file != nullptr && std::setvbuf(file, nullptr, _IONBF, 0) != 0) {
        std::fclose(file);
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
        return {};
    }
    return FilePtr(file);
}

bool write_file(const std::string& path, const std::uint8_t* data, std::size_t size) {
    const std::filesystem::path destination(path);
    const std::filesystem::path temporary = path + ".tmp";
    {
        FilePtr file = create_private_output(temporary);
        if (!file) return false;
        if ((size != 0 && std::fwrite(data, 1, size, file.get()) != size) ||
            std::fflush(file.get()) != 0) {
            file.reset();
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

bool prepare_output_directory(const std::string& output_path) {
    const std::filesystem::path parent = std::filesystem::path(output_path).parent_path();
    if (parent.empty()) {
        return true;
    }
    std::error_code error;
    std::filesystem::create_directories(parent, error);
    if (error) {
        std::cerr << "Не удалось создать папку для файла «" << output_path
                  << "»: " << error.message() << ".\n";
        return false;
    }
    return true;
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

struct OwnedModuleBuffer {
    const CipherModuleApi* api = nullptr;
    std::uint8_t* data = nullptr;
    std::size_t size = 0;

    ~OwnedModuleBuffer() {
        if (api != nullptr && data != nullptr) api->free_buffer(data, size);
    }
};

// Формат файла пары ключей: сигнатура, длины и содержимое двух ключей.
constexpr std::array<std::uint8_t, 8> KEY_PAIR_MAGIC{
    'C', 'R', 'Y', 'P', 'K', 'E', 'Y', '1'};

void append_u64(SecureBytes& output, std::uint64_t value) {
    for (std::size_t index = 0; index < sizeof(value); ++index) {
        output.push_back(static_cast<std::uint8_t>(value >> (index * 8)));
    }
}

bool read_u64(const SecureBytes& input,
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
                       SecureBytes& encryption_key,
                       SecureBytes& decryption_key) {
    const auto* api = module.api();
    OwnedModuleBuffer encryption{api};
    OwnedModuleBuffer decryption{api};
    std::size_t encryption_size = 0;
    std::size_t decryption_size = 0;
    if (api->generate_keys(nullptr, 0, &encryption.data, &encryption_size,
                           &decryption.data, &decryption_size) != CIPHER_MODULE_STATUS_OK ||
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

SecureBytes make_key_pair_record(
    const SecureBytes& encryption_key,
    const SecureBytes& decryption_key) {
    SecureBytes record(KEY_PAIR_MAGIC.begin(), KEY_PAIR_MAGIC.end());
    record.reserve(KEY_PAIR_MAGIC.size() + 2 * sizeof(std::uint64_t) +
                   encryption_key.size() + decryption_key.size());
    append_u64(record, encryption_key.size());
    append_u64(record, decryption_key.size());
    record.insert(record.end(), encryption_key.begin(), encryption_key.end());
    record.insert(record.end(), decryption_key.begin(), decryption_key.end());
    return record;
}

bool select_key(const SecureBytes& record,
                OperationMode mode,
                SecureBytes& key) {
    if (record.size() < KEY_PAIR_MAGIC.size() + 2 * sizeof(std::uint64_t) ||
        !std::equal(KEY_PAIR_MAGIC.begin(), KEY_PAIR_MAGIC.end(), record.begin())) {
        key = record;
        return !key.empty();
    }
    std::uint64_t encryption_size = 0;
    std::uint64_t decryption_size = 0;
    constexpr std::size_t LENGTHS_OFFSET = KEY_PAIR_MAGIC.size();
    constexpr std::size_t DATA_OFFSET = LENGTHS_OFFSET + 2 * sizeof(std::uint64_t);
    if (!read_u64(record, LENGTHS_OFFSET, encryption_size) ||
        !read_u64(record, LENGTHS_OFFSET + sizeof(std::uint64_t), decryption_size) ||
        encryption_size > record.size() - DATA_OFFSET ||
        decryption_size != record.size() - DATA_OFFSET - encryption_size) {
        return false;
    }
    const std::size_t selected_offset = mode == OperationMode::Encrypt
        ? DATA_OFFSET
        : DATA_OFFSET + static_cast<std::size_t>(encryption_size);
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
    FilePtr output = create_private_output(temporary);
    if (!output) return false;
    if (!copy_file_stream(spool, output.get()) || std::fflush(output.get()) != 0) {
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
    std::string path_error;
    if (!validate_file_paths(options, path_error)) {
        std::cerr << path_error << '\n';
        return 2;
    }
    const Cipher cipher = options.algorithm == "hill" ? Cipher::Hill : Cipher::ElGamal;
    CipherModule module;
    std::string error;
    if (!module.load(module_path(cipher, executable_path).string(), error)) {
        std::cerr << "Не удалось загрузить модуль алгоритма: " << error << '\n';
        return 1;
    }

    SecureBytes encryption_key;
    SecureBytes decryption_key;
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
        SecureBytes key_record;
        VectorCleanser key_record_cleanser{key_record};
        const std::size_t key_size = module.api()->get_algorithm_info()->key_size;
        constexpr std::size_t KEY_HEADER_SIZE = 24;
        if (key_size > (std::numeric_limits<std::size_t>::max() - KEY_HEADER_SIZE) / 2) {
            std::cerr << "Библиотека указала недопустимую длину ключа.\n";
            return 1;
        }
        const std::size_t maximum_key_size = KEY_HEADER_SIZE + 2 * key_size;
        const bool key_read = options.key_path == "-"
            ? read_key_stream(stdin, key_record, maximum_key_size)
            : read_file(options.key_path, key_record, maximum_key_size);
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
    // Стандартные буферы FILE не содержат неочищаемых копий открытого текста.
    if (std::setvbuf(input_handle, nullptr, _IONBF, 0) != 0 ||
        std::setvbuf(input_spool.get(), nullptr, _IONBF, 0) != 0 ||
        std::setvbuf(output_spool.get(), nullptr, _IONBF, 0) != 0) {
        std::cerr << "Не удалось настроить двоичные потоки.\n";
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
                              &transform_context) == CIPHER_MODULE_STATUS_OK
        : api->decrypt_stream(key_buffer, read_stream_callback,
                              write_stream_callback, &transform_context) == CIPHER_MODULE_STATUS_OK;
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

int read_menu_choice(int minimum, int maximum) {
    while (true) {
        std::cout << "Выберите пункт: ";
        std::string value;
        if (!std::getline(std::cin, value)) return -1;
        try {
            std::size_t parsed = 0;
            const int choice = std::stoi(value, &parsed);
            if (parsed == value.size() && choice >= minimum && choice <= maximum) {
                return choice;
            }
        } catch (const std::exception&) {
        }
        std::cout << "Введите число от " << minimum << " до " << maximum << ".\n";
    }
}

std::string read_menu_path(const std::string& prompt, const std::string& default_path) {
    std::cout << prompt << " [" << default_path << "]: ";
    std::string path;
    if (!std::getline(std::cin, path) || path.empty()) return default_path;
    return path;
}

int run_interactive_menu(const char* executable_path) {
    while (true) {
        std::cout << "\nПрограмма шифрования и расшифрования\n"
                  << "1. Шифр Хилла\n"
                  << "2. Шифр Эль-Гамаля\n"
                  << "0. Выход\n";
        const int algorithm_choice = read_menu_choice(0, 2);
        if (algorithm_choice < 0) return 1;
        if (algorithm_choice == 0) {
            std::cout << "Вы вышли из программы.\n";
            return 0;
        }

        const std::string algorithm = algorithm_choice == 1 ? "hill" : "elgamal";
        const std::string default_key_path = "keys/" + algorithm + ".keys.bin";
        while (true) {
            std::cout << "\nВыбран шифр: "
                      << (algorithm_choice == 1 ? "Хилла" : "Эль-Гамаля") << "\n"
                      << "1. Зашифровать файл\n"
                      << "2. Расшифровать файл\n"
                      << "3. Создать пару ключей\n"
                      << "0. Назад\n";
            const int operation_choice = read_menu_choice(0, 3);
            if (operation_choice < 0) return 1;
            if (operation_choice == 0) break;

            CommandLineOptions options;
            options.algorithm = algorithm;
            if (operation_choice == 3) {
                options.mode = OperationMode::GenerateKey;
                options.mode_set = true;
                options.save_key_path = read_menu_path(
                    "Куда сохранить пару ключей", default_key_path);
                if (execute_cli(options, executable_path) == 0) {
                    std::cout << "Пара ключей сохранена в «"
                              << options.save_key_path << "».\n";
                }
                continue;
            }

            options.mode = operation_choice == 1
                ? OperationMode::Encrypt : OperationMode::Decrypt;
            options.mode_set = true;
            options.key_path = read_menu_path("Файл пары ключей", default_key_path);
            if (options.key_path == "-") {
                std::cerr << "В меню укажите путь к файлу ключей.\n";
                continue;
            }
            options.input_path = read_menu_path(
                operation_choice == 1 ? "Файл с исходными данными" : "Файл с шифротекстом",
                operation_choice == 1 ? "input.txt" : "encrypted.bin");
            options.output_path = read_menu_path(
                "Файл для результата",
                operation_choice == 1 ? "encrypted.bin" : "decrypted.bin");
            std::string path_error;
            if (options.input_path == "-" || options.output_path == "-") {
                std::cerr << "В меню укажите пути к входному и выходному файлам.\n";
                continue;
            }
            if (!validate_file_paths(options, path_error)) {
                std::cerr << path_error << '\n';
                continue;
            }
            std::error_code filesystem_error;
            const bool key_exists = std::filesystem::exists(options.key_path, filesystem_error);
            if (filesystem_error) {
                std::cerr << "Не удалось проверить файл ключей: "
                          << filesystem_error.message() << '\n';
                continue;
            }
            if (operation_choice == 1 && !key_exists) {
                CommandLineOptions key_options;
                key_options.algorithm = algorithm;
                key_options.mode = OperationMode::GenerateKey;
                key_options.mode_set = true;
                key_options.save_key_path = options.key_path;
                if (execute_cli(key_options, executable_path) != 0) continue;
                std::cout << "Для шифрования автоматически создана пара ключей.\n";
            } else if (!key_exists) {
                std::cerr << "Файл ключей не найден. Сначала выполните шифрование или создайте пару ключей.\n";
                continue;
            }

            if (execute_cli(options, executable_path) == 0) {
                std::cout << "Результат записан в «" << options.output_path << "».\n";
            }
        }
    }
}

}

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
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    if (std::setvbuf(stdin, nullptr, _IONBF, 0) != 0 ||
        std::setvbuf(stdout, nullptr, _IONBF, 0) != 0) {
        std::cerr << "Не удалось настроить стандартные потоки.\n";
        return 1;
    }
    try {
        if (!authenticate_user()) {
            std::cerr << "Доступ к программе закрыт.\n";
            return 1;
        }
        if (options.menu) return run_interactive_menu(executable_path);
        return execute_cli(options, executable_path);
    } catch (const std::exception& exception) {
        std::cerr << "Операция прервана из-за ошибки: " << exception.what() << '\n';
        return 1;
    } catch (...) {
        std::cerr << "Операция прервана из-за неизвестной ошибки.\n";
        return 1;
    }
}
