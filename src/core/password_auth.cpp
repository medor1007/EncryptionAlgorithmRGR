#include "core/password_auth.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace {

constexpr int ITERATIONS = 600000;
constexpr std::size_t SALT_SIZE = 16;
constexpr std::size_t HASH_SIZE = 32;
constexpr char RECORD_VERSION[] = "RGRPASS1";
constexpr char DEFAULT_PASSWORD[] = "qwerty123";

#ifndef _WIN32
bool write_terminal(int descriptor, const char* data, std::size_t size) {
    std::size_t written = 0;
    while (written < size) {
        const ssize_t result = write(descriptor, data + written, size - written);
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) return false;
        written += static_cast<std::size_t>(result);
    }
    return true;
}
#endif

struct MemoryWiper {
    void* data;
    std::size_t size;
    ~MemoryWiper() {
        if (data != nullptr && size != 0) OPENSSL_cleanse(data, size);
    }
};

struct StringWiper {
    std::string& value;
    ~StringWiper() {
        if (!value.empty()) OPENSSL_cleanse(value.data(), value.size());
    }
};

std::string to_hex(const unsigned char* bytes, std::size_t size) {
    static constexpr char HEX_DIGITS[] = "0123456789abcdef";
    std::string result;
    result.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) {
        result.push_back(HEX_DIGITS[bytes[i] >> 4]);
        result.push_back(HEX_DIGITS[bytes[i] & 0x0f]);
    }
    return result;
}

bool from_hex(const std::string& text, unsigned char* output, std::size_t size) {
    if (text.size() != size * 2) {
        return false;
    }
    auto value = [](char symbol) {
        if (symbol >= '0' && symbol <= '9') return symbol - '0';
        if (symbol >= 'a' && symbol <= 'f') return symbol - 'a' + 10;
        if (symbol >= 'A' && symbol <= 'F') return symbol - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < size; ++i) {
        const int high = value(text[i * 2]);
        const int low = value(text[i * 2 + 1]);
        if (high < 0 || low < 0) return false;
        output[i] = static_cast<unsigned char>((high << 4) | low);
    }
    return true;
}

bool derive_hash(const std::string& password,
                 const unsigned char* salt,
                 int iterations,
                 unsigned char* hash) {
    return PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                             salt, static_cast<int>(SALT_SIZE), iterations,
                             EVP_sha256(), static_cast<int>(HASH_SIZE), hash) == 1;
}

std::string read_password(const std::string& prompt, std::string& error) {
#ifdef _WIN32
    HANDLE console = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                 OPEN_EXISTING, 0, nullptr);
    if (console == INVALID_HANDLE_VALUE) {
        error = "Для ввода пароля требуется доступная консоль.";
        return {};
    }
    DWORD original_mode = 0;
    const bool changed = GetConsoleMode(console, &original_mode) != 0 &&
                         SetConsoleMode(console, original_mode & ~ENABLE_ECHO_INPUT) != 0;
    DWORD written = 0;
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), prompt.data(),
              static_cast<DWORD>(prompt.size()), &written, nullptr);
    std::string password;
    char symbol = 0;
    DWORD read = 0;
    while (ReadConsoleA(console, &symbol, 1, &read, nullptr) && read == 1 &&
           symbol != '\r' && symbol != '\n') {
        password.push_back(symbol);
    }
    if (changed) SetConsoleMode(console, original_mode);
    CloseHandle(console);
    std::cerr << '\n';
#else
    const int console = open("/dev/tty", O_RDWR | O_CLOEXEC);
    if (console < 0) {
        error = "Для парольной проверки требуется подключённый терминал (/dev/tty).";
        return {};
    }
    termios original_settings{};
    const bool changed = tcgetattr(console, &original_settings) == 0;
    if (changed) {
        termios hidden_settings = original_settings;
        hidden_settings.c_lflag &= static_cast<tcflag_t>(~ECHO);
        tcsetattr(console, TCSAFLUSH, &hidden_settings);
    }
    if (!write_terminal(console, prompt.data(), prompt.size())) {
        if (changed) tcsetattr(console, TCSAFLUSH, &original_settings);
        close(console);
        error = "Не удалось вывести приглашение для ввода пароля.";
        return {};
    }
    std::string password;
    char symbol = 0;
    while (read(console, &symbol, 1) == 1 && symbol != '\n' && symbol != '\r') {
        password.push_back(symbol);
    }
    if (changed) tcsetattr(console, TCSAFLUSH, &original_settings);
    if (!write_terminal(console, "\n", 1)) {
        error = "Не удалось завершить ввод пароля.";
    }
    close(console);
#endif
    return password;
}

bool save_record(const std::filesystem::path& path,
                 const std::string& record,
                 std::string& error) {
    std::error_code filesystem_error;
    if (!path.parent_path().empty()) {
        std::filesystem::create_directories(path.parent_path(), filesystem_error);
        if (filesystem_error) {
            error = "Не удалось создать папку для файла пароля: " + filesystem_error.message();
            return false;
        }
    }

    const std::filesystem::path temporary = path.string() + ".tmp";
    {
        std::ofstream file(temporary, std::ios::binary | std::ios::trunc);
        if (!file || !(file << record << '\n') || !file.good()) {
            error = "Не удалось записать файл пароля.";
            std::filesystem::remove(temporary, filesystem_error);
            return false;
        }
    }
#ifndef _WIN32
    if (chmod(temporary.c_str(), S_IRUSR | S_IWUSR) != 0) {
        error = "Не удалось ограничить доступ к файлу пароля.";
        std::filesystem::remove(temporary, filesystem_error);
        return false;
    }
#endif
    std::filesystem::rename(temporary, path, filesystem_error);
    if (filesystem_error) {
        error = "Не удалось сохранить файл пароля: " + filesystem_error.message();
        std::filesystem::remove(temporary, filesystem_error);
        return false;
    }
    error.clear();
    return true;
}

}

bool create_password_record(const std::filesystem::path& path,
                            const std::string& password,
                            std::string& error) {
    if (password.size() < 8 || password.size() > 1024) {
        error = "Пароль должен содержать от 8 до 1024 символов.";
        return false;
    }

    std::array<unsigned char, SALT_SIZE> salt{};
    std::array<unsigned char, HASH_SIZE> hash{};
    MemoryWiper salt_wiper{salt.data(), salt.size()};
    MemoryWiper hash_wiper{hash.data(), hash.size()};
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1 ||
        !derive_hash(password, salt.data(), ITERATIONS, hash.data())) {
        error = "Не удалось подготовить криптографическую запись пароля.";
        return false;
    }
    std::string record = std::string(RECORD_VERSION) + "$" +
        std::to_string(ITERATIONS) + "$" + to_hex(salt.data(), salt.size()) + "$" +
        to_hex(hash.data(), hash.size());
    StringWiper record_wiper{record};
    return save_record(path, record, error);
}

bool verify_password_record(const std::filesystem::path& path,
                            const std::string& password,
                            std::string& error) {
    std::ifstream file(path, std::ios::binary);
    std::string record;
    if (!file || !std::getline(file, record)) {
        error = "Не удалось прочитать файл пароля.";
        return false;
    }

    std::istringstream fields(record);
    std::string version, iterations_text, salt_text, hash_text, extra;
    if (!std::getline(fields, version, '$') || !std::getline(fields, iterations_text, '$') ||
        !std::getline(fields, salt_text, '$') || !std::getline(fields, hash_text, '$') ||
        std::getline(fields, extra, '$') || version != RECORD_VERSION) {
        error = "Файл пароля повреждён или имеет неизвестный формат.";
        return false;
    }

    int iterations = 0;
    try {
        std::size_t parsed = 0;
        iterations = std::stoi(iterations_text, &parsed);
        if (parsed != iterations_text.size() || iterations < 100000 || iterations > 2000000) {
            throw std::invalid_argument("invalid iterations");
        }
    } catch (const std::exception&) {
        error = "Файл пароля содержит некорректные параметры.";
        return false;
    }

    std::array<unsigned char, SALT_SIZE> salt{};
    std::array<unsigned char, HASH_SIZE> expected_hash{};
    std::array<unsigned char, HASH_SIZE> actual_hash{};
    MemoryWiper salt_wiper{salt.data(), salt.size()};
    MemoryWiper expected_hash_wiper{expected_hash.data(), expected_hash.size()};
    MemoryWiper actual_hash_wiper{actual_hash.data(), actual_hash.size()};
    if (!from_hex(salt_text, salt.data(), salt.size()) ||
        !from_hex(hash_text, expected_hash.data(), expected_hash.size()) ||
        !derive_hash(password, salt.data(), iterations, actual_hash.data())) {
        error = "Файл пароля содержит некорректные данные.";
        return false;
    }
    if (CRYPTO_memcmp(expected_hash.data(), actual_hash.data(), expected_hash.size()) != 0) {
        error = "Введён неверный пароль.";
        return false;
    }
    error.clear();
    return true;
}

bool authenticate_user() {
    const std::filesystem::path password_path("config/access.dat");
    std::error_code filesystem_error;
    const bool exists = std::filesystem::exists(password_path, filesystem_error);
    if (filesystem_error) {
        std::cerr << "Не удалось проверить файл пароля: " << filesystem_error.message() << '\n';
        return false;
    }

    std::string error;
    if (!exists) {
        if (!create_password_record(password_path, DEFAULT_PASSWORD, error)) {
            std::cerr << error << '\n';
            return false;
        }
        std::cerr << "Создан файл настроек для стандартного пароля.\n";
    }

    std::string password = read_password("Введите пароль: ", error);
    StringWiper password_wiper{password};
    if (!error.empty()) {
        std::cerr << error << '\n';
        return false;
    }
    if (!verify_password_record(password_path, password, error)) {
        std::cerr << error << '\n';
        return false;
    }
    std::cerr << "Вход выполнен.\n";
    return true;
}
