#include "core/cipher_module.hpp"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <iostream>
#include <string>
#include <vector>

namespace {

struct ModuleBuffer {
    const CipherModuleApi* api = nullptr;
    std::uint8_t* data = nullptr;

    ~ModuleBuffer() {
        if (api != nullptr && data != nullptr) {
            api->free_buffer(data);
        }
    }
};

bool check_round_trip(const CipherModuleApi* api,
                      const std::vector<std::uint8_t>& encryption_key,
                      const std::vector<std::uint8_t>& decryption_key,
                      const std::vector<std::uint8_t>& plaintext,
                      const char* case_name) {
    ModuleBuffer encrypted{api};
    std::size_t encrypted_size = 0;
    if (api->encrypt(encryption_key.data(), encryption_key.size(),
                     plaintext.data(), plaintext.size(),
                     &encrypted.data, &encrypted_size) == 0) {
        std::cerr << "Ошибка шифрования: " << case_name << '\n';
        return false;
    }

    ModuleBuffer decrypted{api};
    std::size_t decrypted_size = 0;
    if (api->decrypt(decryption_key.data(), decryption_key.size(),
                     encrypted.data, encrypted_size,
                     &decrypted.data, &decrypted_size) == 0) {
        std::cerr << "Ошибка расшифрования: " << case_name << '\n';
        return false;
    }
    if (decrypted_size != plaintext.size() ||
        (decrypted_size != 0 &&
         !std::equal(plaintext.begin(), plaintext.end(), decrypted.data))) {
        std::cerr << "После расшифрования данные отличаются: " << case_name << '\n';
        return false;
    }
    return true;
}

bool check_module(const std::string& library_path) {
    CipherModule absent_module;
    std::string error;
    if (absent_module.load(library_path + ".missing", error)) {
        std::cerr << "Загрузчик принял отсутствующую библиотеку.\n";
        return false;
    }

    CipherModule module;
    error.clear();
    if (!module.load(library_path, error)) {
        std::cerr << "Не удалось загрузить модуль «" << library_path << "»: "
                  << error << '\n';
        return false;
    }

    const CipherModuleApi* api = module.api();
    ModuleBuffer encryption_key{api};
    ModuleBuffer decryption_key{api};
    std::size_t encryption_key_size = 0;
    std::size_t decryption_key_size = 0;
    if (api->generate_keys(nullptr, 0,
                           &encryption_key.data, &encryption_key_size,
                           &decryption_key.data, &decryption_key_size) == 0) {
        std::cerr << "Не удалось создать ключи для «" << module.name() << "».\n";
        return false;
    }

    const std::vector<std::uint8_t> public_key(
        encryption_key.data, encryption_key.data + encryption_key_size);
    const std::vector<std::uint8_t> private_key(
        decryption_key.data, decryption_key.data + decryption_key_size);
    const std::vector<std::uint8_t> binary_data{
        0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff, 0x00, 0xc3, 0xa9, 0x0a};
    if (!check_round_trip(api, public_key, private_key,
                          binary_data, "двоичные данные")) {
        return false;
    }
    if (!check_round_trip(api, public_key, private_key,
                          {}, "пустые данные")) {
        return false;
    }

    const std::vector<std::uint8_t> invalid_key{0x01, 0x02, 0x03};
    ModuleBuffer invalid_encryption{api};
    std::size_t invalid_encryption_size = 0;
    if (api->encrypt(invalid_key.data(), invalid_key.size(),
                     binary_data.data(), binary_data.size(),
                     &invalid_encryption.data, &invalid_encryption_size) != 0) {
        std::cerr << "Модуль принял ключ неверного формата: " << module.name() << '\n';
        return false;
    }

    const std::vector<std::uint8_t> invalid_ciphertext{0x00, 0x01, 0x02};
    ModuleBuffer invalid_result{api};
    std::size_t invalid_result_size = 0;
    if (api->decrypt(invalid_key.data(), invalid_key.size(),
                     invalid_ciphertext.data(), invalid_ciphertext.size(),
                     &invalid_result.data, &invalid_result_size) != 0) {
        std::cerr << "Модуль принял ключ дешифрования неверного формата: "
                  << module.name() << '\n';
        return false;
    }
    if (api->decrypt(private_key.data(), private_key.size(),
                     invalid_ciphertext.data(), invalid_ciphertext.size(),
                     &invalid_result.data, &invalid_result_size) != 0) {
        std::cerr << "Модуль принял повреждённый шифротекст: "
                  << module.name() << '\n';
        return false;
    }

    std::cout << "Проверен модуль: " << module.name() << '\n';
    return true;
}

}  // Анонимное пространство имён.

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Укажите пути к двум модулям шифрования.\n";
        return 2;
    }

    try {
        if (!check_module(argv[1]) || !check_module(argv[2])) {
            return 1;
        }
    } catch (const std::exception& error) {
        std::cerr << "Проверка завершилась с исключением: " << error.what() << '\n';
        return 1;
    } catch (...) {
        std::cerr << "Проверка завершилась с неизвестной ошибкой.\n";
        return 1;
    }

    std::cout << "Все проверки модулей пройдены.\n";
    return 0;
}
