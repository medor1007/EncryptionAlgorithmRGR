#include "core/cipher_module.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <string>
#include <vector>

namespace {

struct ModuleBuffer {
    const CipherModuleApi* api = nullptr;
    std::uint8_t* data = nullptr;
    std::size_t size = 0;

    ~ModuleBuffer() {
        if (api != nullptr && data != nullptr) {
            api->free_buffer(data, size);
        }
    }
};

bool transform(const CipherModuleApi* api,
               bool encrypting,
               const std::vector<std::uint8_t>& key,
               const std::uint8_t* input,
               std::size_t input_size,
               ModuleBuffer& output) {
    const int operation = encrypting ? CIPHER_OPERATION_ENCRYPT
                                    : CIPHER_OPERATION_DECRYPT;
    const std::size_t capacity = api->get_output_size(input_size, operation);
    if (capacity == 0) return false;
    output.data = static_cast<std::uint8_t*>(std::malloc(capacity));
    if (output.data == nullptr) return false;
    output.size = capacity;
    MutBuffer output_buffer{output.data, capacity};
    const ConstBuffer key_buffer{key.data(), key.size()};
    const ConstBuffer input_buffer{input, input_size};
    const int succeeded = encrypting
        ? api->encrypt(key_buffer, input_buffer, &output_buffer)
        : api->decrypt(key_buffer, input_buffer, &output_buffer);
    if (succeeded == 0) {
        api->free_buffer(output.data, output.size);
        output.data = nullptr;
        output.size = 0;
        return false;
    }
    output.size = output_buffer.size;
    return true;
}

bool check_round_trip(const CipherModuleApi* api,
                      const std::vector<std::uint8_t>& encryption_key,
                      const std::vector<std::uint8_t>& decryption_key,
                      const std::vector<std::uint8_t>& plaintext,
                      const char* case_name,
                      const std::vector<std::uint8_t>* wrong_decryption_key = nullptr) {
    ModuleBuffer encrypted{api};
    if (!transform(api, true, encryption_key, plaintext.data(),
                   plaintext.size(), encrypted)) {
        std::cerr << "Ошибка шифрования: " << case_name << '\n';
        return false;
    }

    if (wrong_decryption_key != nullptr) {
        ModuleBuffer wrong_result{api};
        if (transform(api, false, *wrong_decryption_key, encrypted.data,
                      encrypted.size, wrong_result)) {
            std::cerr << "Модуль не обнаружил неверный ключ: " << case_name << '\n';
            return false;
        }
    }

    ModuleBuffer decrypted{api};
    if (!transform(api, false, decryption_key, encrypted.data,
                   encrypted.size, decrypted)) {
        std::cerr << "Ошибка расшифрования: " << case_name << '\n';
        return false;
    }
    if (decrypted.size != plaintext.size() ||
        (decrypted.size != 0 &&
         !std::equal(plaintext.begin(), plaintext.end(), decrypted.data))) {
        std::cerr << "После расшифрования данные отличаются: " << case_name << '\n';
        return false;
    }

    constexpr std::size_t legacy_header_size = 12;
    constexpr std::size_t current_header_size = 44;
    const bool is_hill = encrypted.size >= current_header_size &&
                         std::memcmp(encrypted.data, "HIL2", 4) == 0;
    const bool is_elgamal = encrypted.size >= current_header_size &&
                            std::memcmp(encrypted.data, "ELG2", 4) == 0;
    if (is_hill || is_elgamal) {
        std::vector<std::uint8_t> legacy_ciphertext;
        legacy_ciphertext.reserve(legacy_header_size + encrypted.size - current_header_size);
        const char* legacy_magic = is_hill ? "HIL1" : "ELG1";
        legacy_ciphertext.insert(legacy_ciphertext.end(), legacy_magic, legacy_magic + 4);
        legacy_ciphertext.insert(legacy_ciphertext.end(), encrypted.data + 4,
                                 encrypted.data + legacy_header_size);
        legacy_ciphertext.insert(legacy_ciphertext.end(),
                                 encrypted.data + current_header_size,
                                 encrypted.data + encrypted.size);

        ModuleBuffer legacy_decrypted{api};
        if (!transform(api, false, decryption_key, legacy_ciphertext.data(),
                       legacy_ciphertext.size(), legacy_decrypted) ||
            legacy_decrypted.size != plaintext.size() ||
            (legacy_decrypted.size != 0 &&
             !std::equal(plaintext.begin(), plaintext.end(), legacy_decrypted.data))) {
            std::cerr << "Не удалось расшифровать контейнер старого формата: "
                      << case_name << '\n';
            return false;
        }
    }

    std::vector<std::uint8_t> modified_ciphertext(
        encrypted.data, encrypted.data + encrypted.size);
    modified_ciphertext.back() ^= 0x01;
    ModuleBuffer modified_result{api};
    if (transform(api, false, decryption_key, modified_ciphertext.data(),
                  modified_ciphertext.size(), modified_result)) {
        std::cerr << "Модуль не обнаружил повреждение данных: " << case_name << '\n';
        return false;
    }
    std::cout << "[OK] " << api->get_algorithm_info()->algorithm_name
              << ": " << case_name << '\n';
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
    encryption_key.size = encryption_key_size;
    decryption_key.size = decryption_key_size;

    const std::vector<std::uint8_t> public_key(
        encryption_key.data, encryption_key.data + encryption_key_size);
    const std::vector<std::uint8_t> private_key(
        decryption_key.data, decryption_key.data + decryption_key_size);
    ModuleBuffer other_public_key{api};
    ModuleBuffer other_private_key{api};
    std::size_t other_public_key_size = 0;
    std::size_t other_private_key_size = 0;
    if (api->generate_keys(nullptr, 0,
                           &other_public_key.data, &other_public_key_size,
                           &other_private_key.data, &other_private_key_size) == 0) {
        std::cerr << "Не удалось создать дополнительную пару ключей для проверки.\n";
        return false;
    }
    other_public_key.size = other_public_key_size;
    other_private_key.size = other_private_key_size;
    const std::vector<std::uint8_t> other_private_key_bytes(
        other_private_key.data, other_private_key.data + other_private_key_size);
    const std::vector<std::uint8_t> binary_data{
        0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff, 0x00, 0xc3, 0xa9, 0x0a};
    const std::string text = "Проверка шифрования: Hello, 2026!";
    const std::vector<std::uint8_t> text_data(text.begin(), text.end());
    if (!check_round_trip(api, public_key, private_key,
                          text_data, "текст UTF-8",
                          &other_private_key_bytes)) {
        return false;
    }
    if (!check_round_trip(api, public_key, private_key,
                          binary_data, "двоичные данные",
                          &other_private_key_bytes)) {
        return false;
    }
    if (!check_round_trip(api, public_key, private_key,
                          {}, "пустые данные")) {
        return false;
    }

    const std::vector<std::uint8_t> invalid_key{0x01, 0x02, 0x03};
    ModuleBuffer invalid_encryption{api};
    if (transform(api, true, invalid_key, binary_data.data(),
                  binary_data.size(), invalid_encryption)) {
        std::cerr << "Модуль принял ключ неверного формата: " << module.name() << '\n';
        return false;
    }

    std::vector<std::uint8_t> malformed_public_key = public_key;
    std::fill(malformed_public_key.begin(), malformed_public_key.end(), 0);
    ModuleBuffer valid_ciphertext{api};
    if (!transform(api, true, public_key, binary_data.data(),
                   binary_data.size(), valid_ciphertext)) {
        std::cerr << "Не удалось создать данные для проверки ключа: "
                  << module.name() << '\n';
        return false;
    }
    ModuleBuffer malformed_public_result{api};
    if (transform(api, true, malformed_public_key, binary_data.data(),
                  binary_data.size(), malformed_public_result)) {
        std::cerr << "Модуль принял повреждённый ключ шифрования: "
                  << module.name() << '\n';
        return false;
    }
    std::vector<std::uint8_t> malformed_private_key = private_key;
    std::fill(malformed_private_key.begin(), malformed_private_key.end(), 0);
    ModuleBuffer malformed_private_result{api};
    if (transform(api, false, malformed_private_key, valid_ciphertext.data,
                  valid_ciphertext.size, malformed_private_result)) {
        std::cerr << "Модуль принял повреждённый ключ расшифрования: "
                  << module.name() << '\n';
        return false;
    }

    if (std::string(module.name()).find("Хилл") != std::string::npos) {
        const std::vector<std::uint8_t> non_invertible_key{2, 0, 0, 2};
        ModuleBuffer non_invertible_result{api};
        if (transform(api, true, non_invertible_key, binary_data.data(),
                      binary_data.size(), non_invertible_result)) {
            std::cerr << "Шифр Хилла принял необратимую матрицу ключа.\n";
            return false;
        }

        if (transform(api, false, non_invertible_key, valid_ciphertext.data,
                      valid_ciphertext.size, non_invertible_result)) {
            std::cerr << "Шифр Хилла принял необратимую матрицу при расшифровании.\n";
            return false;
        }
    }

    const std::vector<std::uint8_t> invalid_ciphertext{0x00, 0x01, 0x02};
    ModuleBuffer invalid_result{api};
    if (transform(api, false, invalid_key, invalid_ciphertext.data(),
                  invalid_ciphertext.size(), invalid_result)) {
        std::cerr << "Модуль принял ключ дешифрования неверного формата: "
                  << module.name() << '\n';
        return false;
    }
    if (transform(api, false, private_key, invalid_ciphertext.data(),
                  invalid_ciphertext.size(), invalid_result)) {
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

    std::cout << "Пройдено проверок: 6 из 6\n";
    return 0;
}
