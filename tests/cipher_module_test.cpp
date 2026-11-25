#include "core/cipher_module.hpp"

#include <openssl/evp.h>
#include <openssl/bn.h>

#include <algorithm>
#include <array>
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

struct MemoryStream {
    const std::vector<std::uint8_t>* input = nullptr;
    std::size_t position = 0;
    std::vector<std::uint8_t> output;
};

int read_memory_stream(void* context, std::uint8_t* buffer,
                       std::size_t capacity, std::size_t* bytes_read) {
    if (context == nullptr || buffer == nullptr || bytes_read == nullptr) return 0;
    auto* stream = static_cast<MemoryStream*>(context);
    const std::size_t count = std::min(capacity, stream->input->size() - stream->position);
    std::copy_n(stream->input->begin() + static_cast<std::ptrdiff_t>(stream->position),
                count, buffer);
    stream->position += count;
    *bytes_read = count;
    return 1;
}

int write_memory_stream(void* context, const std::uint8_t* buffer, std::size_t size) {
    if (context == nullptr || (buffer == nullptr && size != 0)) return 0;
    auto* stream = static_cast<MemoryStream*>(context);
    stream->output.insert(stream->output.end(), buffer, buffer + size);
    return 1;
}

bool check_stream_round_trip(const CipherModuleApi* api,
                             const std::vector<std::uint8_t>& encryption_key,
                             const std::vector<std::uint8_t>& decryption_key,
                             std::size_t input_size) {
    std::vector<std::uint8_t> plaintext(input_size);
    for (std::size_t index = 0; index < plaintext.size(); ++index) {
        plaintext[index] = static_cast<std::uint8_t>((index * 37) & 0xff);
    }
    std::array<std::uint8_t, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_size = 0;
    if (EVP_Digest(plaintext.empty() ? nullptr : plaintext.data(), plaintext.size(),
                   digest.data(), &digest_size, EVP_sha256(), nullptr) != 1 ||
        digest_size != 32) return false;

    MemoryStream stream{&plaintext, 0, {}};
    const ConstBuffer encryption_key_buffer{encryption_key.data(), encryption_key.size()};
    const auto encrypt_stream = [&](MemoryStream& destination) {
        return api->encrypt_stream_for_test != nullptr
            ? api->encrypt_stream_for_test(encryption_key_buffer, plaintext.size(), digest.data(),
                                            17, read_memory_stream, write_memory_stream, &destination)
            : api->encrypt_stream(encryption_key_buffer, plaintext.size(), digest.data(),
                                   read_memory_stream, write_memory_stream, &destination);
    };
    if (encrypt_stream(stream) != CIPHER_MODULE_STATUS_OK) {
        std::cerr << "Ошибка потокового шифрования, длина " << input_size << '\n';
        return false;
    }
    MemoryStream repeated{&plaintext, 0, {}};
    if (encrypt_stream(repeated) != CIPHER_MODULE_STATUS_OK || repeated.output != stream.output) {
        std::cerr << "Потоковый тест не воспроизводится.\n";
        return false;
    }
    const std::vector<std::uint8_t> ciphertext = stream.output;
    stream.input = &ciphertext;
    stream.position = 0;
    stream.output.clear();
    const ConstBuffer decryption_key_buffer{decryption_key.data(), decryption_key.size()};
    if (api->decrypt_stream(decryption_key_buffer, read_memory_stream,
                            write_memory_stream, &stream) != CIPHER_MODULE_STATUS_OK ||
        stream.output != plaintext) {
        std::cerr << "Ошибка потокового расшифрования, длина " << input_size << '\n';
        return false;
    }
    std::cout << "[OK] Потоковая обработка: " << input_size << " байт\n";
    return true;
}

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
        ? (api->encrypt_for_test != nullptr
               ? api->encrypt_for_test(key_buffer, input_buffer, 17, &output_buffer)
               : api->encrypt(key_buffer, input_buffer, &output_buffer))
        : api->decrypt(key_buffer, input_buffer, &output_buffer);
    if (succeeded != CIPHER_MODULE_STATUS_OK) {
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
    ModuleBuffer repeated_encryption{api};
    if (!transform(api, true, encryption_key, plaintext.data(),
                   plaintext.size(), repeated_encryption) ||
        repeated_encryption.size != encrypted.size ||
        !std::equal(encrypted.data, encrypted.data + encrypted.size,
                    repeated_encryption.data)) {
        std::cerr << "Операция тестирования не детерминирована: " << case_name << '\n';
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

// Старые контейнеры задаются явно: новые операции создают только формат версии 3.
bool check_legacy_formats(const CipherModuleApi* api,
                          const std::vector<std::uint8_t>& private_key,
                          bool is_hill) {
    const std::vector<std::uint8_t> plaintext{0};
    std::array<std::uint8_t, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_size = 0;
    if (EVP_Digest(plaintext.data(), plaintext.size(), digest.data(), &digest_size,
                   EVP_sha256(), nullptr) != 1 || digest_size != 32) return false;
    for (const char version : {'1', '2'}) {
        const std::string magic = std::string(is_hill ? "HIL" : "ELG") + version;
        std::vector<std::uint8_t> ciphertext(magic.begin(), magic.end());
        ciphertext.resize(version == '1' ? 12 : 44, 0);
        ciphertext[4] = 1;
        if (version == '2') std::copy_n(digest.begin(), 32, ciphertext.begin() + 12);
        const std::size_t offset = ciphertext.size();
        ciphertext.resize(offset + (is_hill ? 2 : 512), 0);
        if (!is_hill) {
            // При x = 2 и r = 3: a = 8, b = 2^2040 * 64 = 2^2046.
            ciphertext[offset + 255] = 8;
            ciphertext[offset + 256] = 64;
        }
        ModuleBuffer restored{api};
        if (!transform(api, false, private_key, ciphertext.data(), ciphertext.size(),
                       restored) || restored.size != 1 || restored.data[0] != 0) {
            std::cerr << "Ошибка чтения старого контейнера " << magic << '\n';
            return false;
        }
        MemoryStream stream{&ciphertext, 0, {}};
        const ConstBuffer key{private_key.data(), private_key.size()};
        if (api->decrypt_stream(key, read_memory_stream, write_memory_stream, &stream) !=
                CIPHER_MODULE_STATUS_OK || stream.output != plaintext) {
            std::cerr << "Ошибка потокового чтения старого контейнера " << magic << '\n';
            return false;
        }
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
    std::array<std::uint8_t, 4> fixed_private_exponent{2, 0, 0, 0};
    const int generated = api->generate_keys_for_test != nullptr
        ? api->generate_keys_for_test(fixed_private_exponent.data(),
                                      fixed_private_exponent.size(),
                                      &encryption_key.data, &encryption_key_size,
                                      &decryption_key.data, &decryption_key_size)
        : api->generate_keys(nullptr, 0,
                             &encryption_key.data, &encryption_key_size,
                             &decryption_key.data, &decryption_key_size);
    if (generated != CIPHER_MODULE_STATUS_OK) {
        std::cerr << "Не удалось создать ключи для «" << module.name() << "».\n";
        return false;
    }
    encryption_key.size = encryption_key_size;
    decryption_key.size = decryption_key_size;

    std::vector<std::uint8_t> public_key(
        encryption_key.data, encryption_key.data + encryption_key_size);
    std::vector<std::uint8_t> private_key(
        decryption_key.data, decryption_key.data + decryption_key_size);
    if (std::string(module.name()).find("Хилл") != std::string::npos) {
        public_key = {1, 3, 2, 5};
        private_key = {251, 3, 2, 255};
    }
    ModuleBuffer other_public_key{api};
    ModuleBuffer other_private_key{api};
    std::size_t other_public_key_size = 0;
    std::size_t other_private_key_size = 0;
    fixed_private_exponent[0] = 3;
    const int generated_other = api->generate_keys_for_test != nullptr
        ? api->generate_keys_for_test(fixed_private_exponent.data(),
                                      fixed_private_exponent.size(),
                                      &other_public_key.data, &other_public_key_size,
                                      &other_private_key.data, &other_private_key_size)
        : api->generate_keys(nullptr, 0,
                             &other_public_key.data, &other_public_key_size,
                             &other_private_key.data, &other_private_key_size);
    if (generated_other != CIPHER_MODULE_STATUS_OK) {
        std::cerr << "Не удалось создать дополнительную пару ключей для проверки.\n";
        return false;
    }
    other_public_key.size = other_public_key_size;
    other_private_key.size = other_private_key_size;
    std::vector<std::uint8_t> other_private_key_bytes(
        other_private_key.data, other_private_key.data + other_private_key_size);
    if (std::string(module.name()).find("Хилл") != std::string::npos) {
        other_private_key_bytes = {1, 0, 0, 1};
    }
    const std::vector<std::uint8_t> binary_data{
        0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff, 0x00, 0xc3, 0xa9, 0x0a};
    const std::string text = "Проверка шифрования: Hello, 2026!";
    const std::vector<std::uint8_t> text_data(text.begin(), text.end());
    std::vector<std::uint8_t> boundary_data(509);
    for (std::size_t index = 0; index < boundary_data.size(); ++index) {
        boundary_data[index] = static_cast<std::uint8_t>(index & 0xff);
    }
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
    if (!check_round_trip(api, public_key, private_key,
                          boundary_data, "граничная длина блока")) {
        return false;
    }
    const bool is_hill = std::string(module.name()).find("Хилл") != std::string::npos;
    if (!check_legacy_formats(api, private_key, is_hill)) return false;
    const std::array<std::size_t, 2> stream_sizes = is_hill
        ? std::array<std::size_t, 2>{0, 509}
        : std::array<std::size_t, 2>{254, 508};
    for (const std::size_t stream_size : stream_sizes) {
        if (!check_stream_round_trip(api, public_key, private_key, stream_size)) return false;
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

    if (!is_hill) {
        auto degenerate_private_key = private_key;
        BIGNUM* order = BN_bin2bn(public_key.data() + 4, 256, nullptr);
        if (order == nullptr) return false;
        const bool encoded_order = BN_rshift1(order, order) == 1 &&
            BN_bn2binpad(order, degenerate_private_key.data() + 516, 256) == 256;
        BN_clear_free(order);
        if (!encoded_order) return false;
        ModuleBuffer degenerate_result{api};
        if (transform(api, false, degenerate_private_key, valid_ciphertext.data,
                       valid_ciphertext.size, degenerate_result)) {
            std::cerr << "Принят вырожденный закрытый показатель Эль-Гамаля.\n";
            return false;
        }
        for (int field = 0; field < 3; ++field) {
            auto invalid_group_key = public_key;
            if (field == 0) {
                std::fill(invalid_group_key.begin() + 4, invalid_group_key.begin() + 260, 0xff);
                invalid_group_key[259] = 0xfe;
            } else {
                const std::size_t offset = field == 1 ? 260 : 516;
                std::fill_n(invalid_group_key.begin() + static_cast<std::ptrdiff_t>(offset), 256, 0);
                invalid_group_key[offset + 255] = field == 1 ? 3 : 1;
            }
            ModuleBuffer invalid_group_result{api};
            if (transform(api, true, invalid_group_key, binary_data.data(), binary_data.size(),
                           invalid_group_result)) {
                std::cerr << "Приняты некорректные параметры группы Эль-Гамаля.\n";
                return false;
            }
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

}

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

    std::cout << "Пройдено проверок: 12 из 12\n";
    return 0;
}
