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

constexpr std::array<std::uint8_t, 8> KEY_PAIR_MAGIC{
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

std::vector<std::uint8_t> make_key_pair_record(
    const std::vector<std::uint8_t>& encryption_key,
    const std::vector<std::uint8_t>& decryption_key) {
    std::vector<std::uint8_t> record(KEY_PAIR_MAGIC.begin(), KEY_PAIR_MAGIC.end());
    append_u64(record, encryption_key.size());
    append_u64(record, decryption_key.size());
    record.insert(record.end(), encryption_key.begin(), encryption_key.end());
    record.insert(record.end(), decryption_key.begin(), decryption_key.end());
    return record;
}

bool select_key(const std::vector<std::uint8_t>& record,
                OperationMode mode,
                std::vector<std::uint8_t>& key) {
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
    if (!authenticate_user()) {
        std::cerr << "Доступ к программе закрыт.\n";
        return 1;
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
