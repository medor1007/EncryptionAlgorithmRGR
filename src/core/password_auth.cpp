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
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace {

// Параметры записи пароля.
constexpr int kIterations = 600000;
constexpr std::size_t kSaltSize = 16;
constexpr std::size_t kHashSize = 32;
constexpr char kRecordVersion[] = "RGRPASS1";
constexpr char kDefaultPassword[] = "qwerty123";

// Преобразование двоичных данных для файла настроек.
std::string to_hex(const unsigned char* bytes, std::size_t size) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) {
        result.push_back(digits[bytes[i] >> 4]);
        result.push_back(digits[bytes[i] & 0x0f]);
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
                             salt, static_cast<int>(kSaltSize), iterations,
                             EVP_sha256(), static_cast<int>(kHashSize), hash) == 1;
}

// Ввод пароля без отображения символов.
std::string read_password(const std::string& prompt) {
    std::cout << prompt;
#ifdef _WIN32
    HANDLE console = GetStdHandle(STD_INPUT_HANDLE);
    DWORD original_mode = 0;
    const bool changed = console != INVALID_HANDLE_VALUE &&
                         GetConsoleMode(console, &original_mode) != 0 &&
                         SetConsoleMode(console, original_mode & ~ENABLE_ECHO_INPUT) != 0;
    std::string password;
    std::getline(std::cin, password);
    if (changed) SetConsoleMode(console, original_mode);
#else
    termios original_settings{};
    const bool changed = isatty(STDIN_FILENO) &&
                         tcgetattr(STDIN_FILENO, &original_settings) == 0;
    if (changed) {
        termios hidden_settings = original_settings;
        hidden_settings.c_lflag &= static_cast<tcflag_t>(~ECHO);
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden_settings);
    }
    std::string password;
    std::getline(std::cin, password);
    if (changed) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_settings);
        std::cout << '\n';
    }
#endif
    return password;
}

// Создание локального файла с хешем пароля.
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

}  // namespace

bool create_password_record(const std::filesystem::path& path,
                            const std::string& password,
                            std::string& error) {
    if (password.size() < 8 || password.size() > 1024) {
        error = "Пароль должен содержать от 8 до 1024 символов.";
        return false;
    }

    std::array<unsigned char, kSaltSize> salt{};
    std::array<unsigned char, kHashSize> hash{};
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1 ||
        !derive_hash(password, salt.data(), kIterations, hash.data())) {
        error = "Не удалось подготовить криптографическую запись пароля.";
        return false;
    }
    const std::string record = std::string(kRecordVersion) + "$" +
        std::to_string(kIterations) + "$" + to_hex(salt.data(), salt.size()) + "$" +
        to_hex(hash.data(), hash.size());
    return save_record(path, record, error);
}

// Проверка введённого пароля по сохранённому хешу.
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
        std::getline(fields, extra, '$') || version != kRecordVersion) {
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

    std::array<unsigned char, kSaltSize> salt{};
    std::array<unsigned char, kHashSize> expected_hash{};
    std::array<unsigned char, kHashSize> actual_hash{};
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
        std::cout << "Не удалось проверить файл пароля: " << filesystem_error.message() << '\n';
        return false;
    }

    std::string error;
    if (!exists) {
        if (!create_password_record(password_path, kDefaultPassword, error)) {
            std::cout << error << '\n';
            return false;
        }
        std::cout << "Создан файл настроек для стандартного пароля.\n";
    }

    const std::string password = read_password("Введите пароль: ");
    if (!verify_password_record(password_path, password, error)) {
        std::cout << error << '\n';
        return false;
    }
    std::cout << "Вход выполнен.\n";
    return true;
}
