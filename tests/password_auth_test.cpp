#include "core/password_auth.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

int main() {
    const auto directory = std::filesystem::temp_directory_path() /
                           "encryption_rgr_password_auth_test";
    const auto password_file = directory / "access.dat";
    std::error_code filesystem_error;
    std::filesystem::remove_all(directory, filesystem_error);

    std::string error;
    if (!create_password_record(password_file, "secure-test-password", error)) {
        std::cerr << "Не удалось создать запись пароля: " << error << '\n';
        return 1;
    }
    std::ifstream stored_file(password_file, std::ios::binary);
    const std::string stored_record((std::istreambuf_iterator<char>(stored_file)),
                                    std::istreambuf_iterator<char>());
    if (stored_record.find("secure-test-password") != std::string::npos) {
        std::cerr << "Пароль сохранён в открытом виде.\n";
        std::filesystem::remove_all(directory, filesystem_error);
        return 1;
    }
    if (!verify_password_record(password_file, "secure-test-password", error)) {
        std::cerr << "Правильный пароль не принят: " << error << '\n';
        std::filesystem::remove_all(directory, filesystem_error);
        return 1;
    }
    if (verify_password_record(password_file, "incorrect-password", error)) {
        std::cerr << "Принят неверный пароль.\n";
        std::filesystem::remove_all(directory, filesystem_error);
        return 1;
    }
    if (create_password_record(password_file, "short", error)) {
        std::cerr << "Принят слишком короткий пароль.\n";
        std::filesystem::remove_all(directory, filesystem_error);
        return 1;
    }

    std::filesystem::remove_all(directory, filesystem_error);
    std::cout << "Проверка парольной защиты пройдена.\n";
    return 0;
}
