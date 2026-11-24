#include "cipher_module_api.h"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <numeric>
#include <random>

namespace {

constexpr std::size_t kKeySize = 4;
constexpr std::size_t kLegacyHeaderSize = 12;
constexpr std::size_t kDigestSize = 32;
constexpr std::size_t kHeaderSize = kLegacyHeaderSize + kDigestSize;
constexpr std::array<std::uint8_t, 4> kLegacyMagic{'H', 'I', 'L', '1'};
constexpr std::array<std::uint8_t, 4> kMagic{'H', 'I', 'L', '2'};

int inverse_mod_256(int value, int& inverse) {
    value %= 256;
    if (value < 0) {
        value += 256;
    }
    if (std::gcd(value, 256) != 1) {
        return 0;
    }

    for (int candidate = 1; candidate < 256; ++candidate) {
        if ((value * candidate) % 256 == 1) {
            inverse = candidate;
            return 1;
        }
    }
    return 0;
}

std::uint8_t mod_256(int value) {
    value %= 256;
    if (value < 0) {
        value += 256;
    }
    return static_cast<std::uint8_t>(value);
}

bool calculate_digest(const std::uint8_t* data,
                      std::size_t size,
                      std::array<std::uint8_t, kDigestSize>& digest) {
    static const std::uint8_t empty_data = 0;
    const std::uint8_t* source = size == 0 ? &empty_data : data;
    unsigned int digest_size = 0;
    return EVP_Digest(source, size, digest.data(), &digest_size,
                      EVP_sha256(), nullptr) == 1 && digest_size == digest.size();
}

int allocate_copy(const std::uint8_t* data, std::size_t size, std::uint8_t** output) {
    if (output == nullptr || (data == nullptr && size != 0)) {
        return 0;
    }
    *output = nullptr;
    if (size == 0) {
        return 1;
    }

    auto* buffer = static_cast<std::uint8_t*>(std::malloc(size));
    if (buffer == nullptr) {
        return 0;
    }
    std::memcpy(buffer, data, size);
    *output = buffer;
    return 1;
}

int generate_keys(const std::uint8_t* parameters,
                  std::size_t parameters_size,
                  std::uint8_t** encryption_key,
                  std::size_t* encryption_key_size,
                  std::uint8_t** decryption_key,
                  std::size_t* decryption_key_size) {
    (void)parameters;
    if (parameters_size != 0 || encryption_key == nullptr ||
        encryption_key_size == nullptr || decryption_key == nullptr ||
        decryption_key_size == nullptr) {
        return 0;
    }

    *encryption_key = nullptr;
    *decryption_key = nullptr;
    *encryption_key_size = 0;
    *decryption_key_size = 0;

    try {
        std::random_device random;
        std::array<std::uint8_t, kKeySize> key{};
        std::array<std::uint8_t, kKeySize> inverse{};
        int determinant_inverse = 0;

        do {
            for (auto& byte : key) {
                byte = static_cast<std::uint8_t>(random());
            }
        } while (!inverse_mod_256(
            static_cast<int>(key[0]) * key[3] - static_cast<int>(key[1]) * key[2],
            determinant_inverse));

        inverse[0] = mod_256(determinant_inverse * key[3]);
        inverse[1] = mod_256(-determinant_inverse * key[1]);
        inverse[2] = mod_256(-determinant_inverse * key[2]);
        inverse[3] = mod_256(determinant_inverse * key[0]);

        if (!allocate_copy(key.data(), key.size(), encryption_key) ||
            !allocate_copy(inverse.data(), inverse.size(), decryption_key)) {
            std::free(*encryption_key);
            std::free(*decryption_key);
            *encryption_key = nullptr;
            *decryption_key = nullptr;
            return 0;
        }

        *encryption_key_size = key.size();
        *decryption_key_size = inverse.size();
        return 1;
    } catch (...) {
        return 0;
    }
}

int encrypt(const std::uint8_t* key,
            std::size_t key_size,
            const std::uint8_t* input,
            std::size_t input_size,
            std::uint8_t** output,
            std::size_t* output_size) {
    if (key == nullptr || key_size != kKeySize || output == nullptr ||
        output_size == nullptr || (input == nullptr && input_size != 0) ||
        input_size > std::numeric_limits<std::uint64_t>::max()) {
        return 0;
    }
    int determinant_inverse = 0;
    if (!inverse_mod_256(static_cast<int>(key[0]) * key[3] -
                         static_cast<int>(key[1]) * key[2],
                         determinant_inverse)) {
        return 0;
    }
    *output = nullptr;
    *output_size = 0;

    const std::size_t padding = input_size % 2;
    if (input_size > std::numeric_limits<std::size_t>::max() - padding) {
        return 0;
    }
    const std::size_t padded_size = input_size + padding;
    if (padded_size > std::numeric_limits<std::size_t>::max() - kHeaderSize) {
        return 0;
    }
    const std::size_t result_size = kHeaderSize + padded_size;
    auto* result = static_cast<std::uint8_t*>(std::malloc(result_size));
    if (result == nullptr) {
        return 0;
    }

    std::copy(kMagic.begin(), kMagic.end(), result);
    const auto original_size = static_cast<std::uint64_t>(input_size);
    for (std::size_t i = 0; i < sizeof(original_size); ++i) {
        result[4 + i] = static_cast<std::uint8_t>((original_size >> (8 * i)) & 0xff);
    }
    std::array<std::uint8_t, kDigestSize> digest{};
    if (!calculate_digest(input, input_size, digest)) {
        std::free(result);
        return 0;
    }
    std::copy(digest.begin(), digest.end(), result + kLegacyHeaderSize);

    for (std::size_t offset = 0; offset < padded_size; offset += 2) {
        const int first = offset < input_size ? input[offset] : 0;
        const int second = offset + 1 < input_size ? input[offset + 1] : 0;
        result[kHeaderSize + offset] = mod_256(first * key[0] + second * key[2]);
        result[kHeaderSize + offset + 1] = mod_256(first * key[1] + second * key[3]);
    }

    *output = result;
    *output_size = result_size;
    return 1;
}

int decrypt(const std::uint8_t* key,
            std::size_t key_size,
            const std::uint8_t* input,
            std::size_t input_size,
            std::uint8_t** output,
            std::size_t* output_size) {
    if (key == nullptr || key_size != kKeySize || input == nullptr ||
        input_size < kLegacyHeaderSize || output == nullptr || output_size == nullptr) {
        return 0;
    }
    int determinant_inverse = 0;
    if (!inverse_mod_256(static_cast<int>(key[0]) * key[3] -
                         static_cast<int>(key[1]) * key[2],
                         determinant_inverse)) {
        return 0;
    }
    *output = nullptr;
    *output_size = 0;

    const bool has_digest = std::equal(kMagic.begin(), kMagic.end(), input);
    if (!has_digest && !std::equal(kLegacyMagic.begin(), kLegacyMagic.end(), input)) {
        return 0;
    }
    const std::size_t header_size = has_digest ? kHeaderSize : kLegacyHeaderSize;
    if (input_size < header_size) {
        return 0;
    }

    std::uint64_t original_size = 0;
    for (std::size_t i = 0; i < sizeof(original_size); ++i) {
        original_size |= static_cast<std::uint64_t>(input[4 + i]) << (8 * i);
    }
    const std::size_t encrypted_size = input_size - header_size;
    if ((encrypted_size % 2) != 0 || original_size > encrypted_size ||
        encrypted_size - original_size > 1 ||
        original_size > std::numeric_limits<std::size_t>::max()) {
        return 0;
    }

    const auto plaintext_size = static_cast<std::size_t>(original_size);
    auto* plaintext = plaintext_size == 0
        ? nullptr
        : static_cast<std::uint8_t*>(std::malloc(plaintext_size));
    if (plaintext_size != 0 && plaintext == nullptr) {
        return 0;
    }

    for (std::size_t offset = 0; offset < encrypted_size; offset += 2) {
        const int first = input[header_size + offset];
        const int second = input[header_size + offset + 1];
        const std::size_t position = offset;
        if (position < plaintext_size) {
            plaintext[position] = mod_256(first * key[0] + second * key[2]);
        }
        if (position + 1 < plaintext_size) {
            plaintext[position + 1] = mod_256(first * key[1] + second * key[3]);
        }
    }

    if (has_digest) {
        std::array<std::uint8_t, kDigestSize> digest{};
        if (!calculate_digest(plaintext, plaintext_size, digest) ||
            !std::equal(digest.begin(), digest.end(), input + kLegacyHeaderSize)) {
            std::free(plaintext);
            return 0;
        }
    }

    *output = plaintext;
    *output_size = plaintext_size;
    return 1;
}

const char* get_name() {
    return "Шифр Хилла (байтовый вариант)";
}

void free_buffer(std::uint8_t* buffer) {
    std::free(buffer);
}

const CipherModuleApi kApi{
    CIPHER_MODULE_ABI_VERSION,
    sizeof(CipherModuleApi),
    get_name,
    generate_keys,
    encrypt,
    decrypt,
    free_buffer,
};

}  // Анонимное пространство имён.

extern "C" CIPHER_MODULE_EXPORT const CipherModuleApi* get_cipher_module_api(void) {
    return &kApi;
}
