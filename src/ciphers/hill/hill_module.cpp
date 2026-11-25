#include "cipher_module_api.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <numeric>

namespace {

constexpr std::size_t KEY_SIZE = 4;
constexpr std::size_t LEGACY_HEADER_SIZE = 12;
constexpr std::size_t DIGEST_SIZE = 32;
constexpr std::size_t HEADER_SIZE = LEGACY_HEADER_SIZE + DIGEST_SIZE;
constexpr std::array<std::uint8_t, 4> LEGACY_MAGIC{'H', 'I', 'L', '1'};
constexpr std::array<std::uint8_t, 4> PREVIOUS_MAGIC{'H', 'I', 'L', '2'};
constexpr std::array<std::uint8_t, 4> MAGIC{'H', 'I', 'L', '3'};

struct MemoryWiper {
    void* data;
    std::size_t size;
    ~MemoryWiper() {
        if (data != nullptr && size != 0) OPENSSL_cleanse(data, size);
    }
};

class StreamReader {
public:
    StreamReader(CipherReadCallback callback, void* context)
        : callback_(callback), context_(context) {}

    bool read_exact(std::uint8_t* destination, std::size_t size) {
        std::size_t copied = 0;
        while (copied < size) {
            if (position_ == available_ && !refill()) return false;
            const std::size_t chunk = std::min(size - copied, available_ - position_);
            std::copy_n(buffer_.begin() + static_cast<std::ptrdiff_t>(position_), chunk,
                        destination + copied);
            position_ += chunk;
            copied += chunk;
        }
        return true;
    }

    bool at_end() {
        return position_ == available_ && refill() && available_ == 0;
    }

private:
    bool refill() {
        position_ = 0;
        available_ = 0;
        if (ended_) return true;
        if (!callback_(context_, buffer_.data(), buffer_.size(), &available_) ||
            available_ > buffer_.size()) return false;
        if (available_ == 0) ended_ = true;
        return true;
    }

    CipherReadCallback callback_;
    void* context_;
    std::array<std::uint8_t, 65536> buffer_{};
    std::size_t position_ = 0;
    std::size_t available_ = 0;
    bool ended_ = false;
};

class StreamWriter {
public:
    StreamWriter(CipherWriteCallback callback, void* context)
        : callback_(callback), context_(context) {}
    ~StreamWriter() { OPENSSL_cleanse(buffer_.data(), buffer_.size()); }

    bool write(const std::uint8_t* data, std::size_t size) {
        std::size_t copied = 0;
        while (copied < size) {
            const std::size_t chunk = std::min(size - copied,
                                               buffer_.size() - buffered_);
            std::copy_n(data + copied, chunk,
                        buffer_.begin() + static_cast<std::ptrdiff_t>(buffered_));
            buffered_ += chunk;
            copied += chunk;
            if (buffered_ == buffer_.size() && !flush()) return false;
        }
        return true;
    }

    bool finish() { return flush(); }

private:
    bool flush() {
        if (buffered_ == 0) return true;
        if (!callback_(context_, buffer_.data(), buffered_)) return false;
        OPENSSL_cleanse(buffer_.data(), buffered_);
        buffered_ = 0;
        return true;
    }

    CipherWriteCallback callback_;
    void* context_;
    std::array<std::uint8_t, 65536> buffer_{};
    std::size_t buffered_ = 0;
};

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
                      std::array<std::uint8_t, DIGEST_SIZE>& digest) {
    static const std::uint8_t EMPTY_DATA = 0;
    const std::uint8_t* source = size == 0 ? &EMPTY_DATA : data;
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

int generate_keys_alloc(const std::uint8_t* parameters,
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
        std::array<std::uint8_t, KEY_SIZE> key{};
        std::array<std::uint8_t, KEY_SIZE> inverse{};
        MemoryWiper key_wiper{key.data(), key.size()};
        MemoryWiper inverse_wiper{inverse.data(), inverse.size()};
        int determinant_inverse = 0;

        do {
            if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) return 0;
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

int encrypt_alloc(const std::uint8_t* key,
            std::size_t key_size,
            const std::uint8_t* input,
            std::size_t input_size,
            std::uint8_t** output,
            std::size_t* output_size) {
    if (key == nullptr || key_size != KEY_SIZE || output == nullptr ||
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

    const std::size_t padding = 2 - input_size % 2;
    if (input_size > std::numeric_limits<std::size_t>::max() - padding) {
        return 0;
    }
    const std::size_t padded_size = input_size + padding;
    if (padded_size > std::numeric_limits<std::size_t>::max() - HEADER_SIZE) {
        return 0;
    }
    const std::size_t result_size = HEADER_SIZE + padded_size;
    auto* result = static_cast<std::uint8_t*>(std::malloc(result_size));
    if (result == nullptr) {
        return 0;
    }

    std::copy(MAGIC.begin(), MAGIC.end(), result);
    const auto original_size = static_cast<std::uint64_t>(input_size);
    for (std::size_t i = 0; i < sizeof(original_size); ++i) {
        result[4 + i] = static_cast<std::uint8_t>((original_size >> (8 * i)) & 0xff);
    }
    std::array<std::uint8_t, DIGEST_SIZE> digest{};
    if (!calculate_digest(input, input_size, digest)) {
        std::free(result);
        return 0;
    }
    std::copy(digest.begin(), digest.end(), result + LEGACY_HEADER_SIZE);

    for (std::size_t offset = 0; offset < padded_size; offset += 2) {
        const int first = offset < input_size
            ? input[offset]
            : static_cast<int>(padding);
        const int second = offset + 1 < input_size
            ? input[offset + 1]
            : static_cast<int>(padding);
        result[HEADER_SIZE + offset] = mod_256(first * key[0] + second * key[2]);
        result[HEADER_SIZE + offset + 1] = mod_256(first * key[1] + second * key[3]);
    }

    *output = result;
    *output_size = result_size;
    return 1;
}

int decrypt_alloc(const std::uint8_t* key,
            std::size_t key_size,
            const std::uint8_t* input,
            std::size_t input_size,
            std::uint8_t** output,
            std::size_t* output_size) {
    if (key == nullptr || key_size != KEY_SIZE || input == nullptr ||
        input_size < LEGACY_HEADER_SIZE || output == nullptr || output_size == nullptr) {
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

    const bool is_current = std::equal(MAGIC.begin(), MAGIC.end(), input);
    const bool has_digest = is_current ||
        std::equal(PREVIOUS_MAGIC.begin(), PREVIOUS_MAGIC.end(), input);
    if (!has_digest && !std::equal(LEGACY_MAGIC.begin(), LEGACY_MAGIC.end(), input)) {
        return 0;
    }
    const std::size_t header_size = has_digest ? HEADER_SIZE : LEGACY_HEADER_SIZE;
    if (input_size < header_size) {
        return 0;
    }

    std::uint64_t original_size = 0;
    for (std::size_t i = 0; i < sizeof(original_size); ++i) {
        original_size |= static_cast<std::uint64_t>(input[4 + i]) << (8 * i);
    }
    const std::size_t encrypted_size = input_size - header_size;
    const std::uint64_t expected_padding = is_current ? 2 - original_size % 2
                                                       : original_size % 2;
    if ((encrypted_size % 2) != 0 || original_size > encrypted_size ||
        encrypted_size - original_size != expected_padding ||
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
        } else if (is_current && mod_256(first * key[0] + second * key[2]) !=
                   expected_padding) {
            if (plaintext_size != 0) OPENSSL_cleanse(plaintext, plaintext_size);
            std::free(plaintext);
            return 0;
        }
        if (position + 1 < plaintext_size) {
            plaintext[position + 1] = mod_256(first * key[1] + second * key[3]);
        } else if (is_current && mod_256(first * key[1] + second * key[3]) !=
                   expected_padding) {
            if (plaintext_size != 0) OPENSSL_cleanse(plaintext, plaintext_size);
            std::free(plaintext);
            return 0;
        }
    }

    if (has_digest) {
        std::array<std::uint8_t, DIGEST_SIZE> digest{};
        if (!calculate_digest(plaintext, plaintext_size, digest) ||
            !std::equal(digest.begin(), digest.end(), input + LEGACY_HEADER_SIZE)) {
            if (plaintext_size != 0) OPENSSL_cleanse(plaintext, plaintext_size);
            std::free(plaintext);
            return 0;
        }
    }

    *output = plaintext;
    *output_size = plaintext_size;
    return 1;
}

void free_buffer_impl(std::uint8_t* buffer, std::size_t buffer_size) {
    if (buffer != nullptr) OPENSSL_cleanse(buffer, buffer_size);
    std::free(buffer);
}

std::uint64_t decode_length(const std::uint8_t* source) {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < sizeof(value); ++index) {
        value |= static_cast<std::uint64_t>(source[index]) << (index * 8);
    }
    return value;
}

void transform_pair(const std::uint8_t* key,
                    int first,
                    int second,
                    std::uint8_t* output) {
    output[0] = mod_256(first * key[0] + second * key[2]);
    output[1] = mod_256(first * key[1] + second * key[3]);
}

int encrypt_stream_impl(ConstBuffer key,
                        std::uint64_t input_size,
                        const std::uint8_t* input_digest,
                        CipherReadCallback read_callback,
                        CipherWriteCallback write_callback,
                        void* context) {
    if (key.data == nullptr || key.size != KEY_SIZE || input_digest == nullptr ||
        read_callback == nullptr || write_callback == nullptr ||
        input_size > std::numeric_limits<std::size_t>::max()) return 0;
    int determinant_inverse = 0;
    if (!inverse_mod_256(static_cast<int>(key.data[0]) * key.data[3] -
                         static_cast<int>(key.data[1]) * key.data[2],
                         determinant_inverse)) return 0;

    std::array<std::uint8_t, HEADER_SIZE> header{};
    std::copy(MAGIC.begin(), MAGIC.end(), header.begin());
    for (std::size_t index = 0; index < sizeof(input_size); ++index) {
        header[4 + index] = static_cast<std::uint8_t>(input_size >> (index * 8));
    }
    std::copy_n(input_digest, DIGEST_SIZE, header.begin() + LEGACY_HEADER_SIZE);
    StreamReader reader(read_callback, context);
    StreamWriter writer(write_callback, context);
    if (!writer.write(header.data(), header.size())) return 0;

    std::array<std::uint8_t, 65536> input_buffer{};
    std::array<std::uint8_t, 65536> output_buffer{};
    std::uint64_t remaining = input_size;
    while (remaining >= 2) {
        const std::size_t chunk_size = static_cast<std::size_t>(
            std::min<std::uint64_t>(remaining & ~std::uint64_t{1}, input_buffer.size()));
        if (!reader.read_exact(input_buffer.data(), chunk_size)) return 0;
        for (std::size_t offset = 0; offset < chunk_size; offset += 2) {
            transform_pair(key.data, input_buffer[offset], input_buffer[offset + 1],
                           output_buffer.data() + offset);
        }
        if (!writer.write(output_buffer.data(), chunk_size)) return 0;
        remaining -= chunk_size;
    }
    if (remaining == 1) {
        std::uint8_t final_byte = 0;
        std::array<std::uint8_t, 2> encrypted_pair{};
        if (!reader.read_exact(&final_byte, 1)) return 0;
        transform_pair(key.data, final_byte, 1, encrypted_pair.data());
        if (!writer.write(encrypted_pair.data(), encrypted_pair.size())) return 0;
    } else {
        const std::array<std::uint8_t, 2> padding{2, 2};
        std::array<std::uint8_t, 2> encrypted_pair{};
        transform_pair(key.data, padding[0], padding[1], encrypted_pair.data());
        if (!writer.write(encrypted_pair.data(), encrypted_pair.size())) return 0;
    }
    return reader.at_end() && writer.finish() ? 1 : 0;
}

int decrypt_stream_impl(ConstBuffer key,
                        CipherReadCallback read_callback,
                        CipherWriteCallback write_callback,
                        void* context) {
    if (key.data == nullptr || key.size != KEY_SIZE ||
        read_callback == nullptr || write_callback == nullptr) return 0;
    int determinant_inverse = 0;
    if (!inverse_mod_256(static_cast<int>(key.data[0]) * key.data[3] -
                         static_cast<int>(key.data[1]) * key.data[2],
                         determinant_inverse)) return 0;

    StreamReader reader(read_callback, context);
    StreamWriter writer(write_callback, context);
    std::array<std::uint8_t, HEADER_SIZE> header{};
    if (!reader.read_exact(header.data(), LEGACY_HEADER_SIZE)) return 0;
    const bool is_current = std::equal(MAGIC.begin(), MAGIC.end(), header.begin());
    const bool has_digest = is_current ||
        std::equal(PREVIOUS_MAGIC.begin(), PREVIOUS_MAGIC.end(), header.begin());
    const bool is_legacy = std::equal(LEGACY_MAGIC.begin(), LEGACY_MAGIC.end(), header.begin());
    if (!has_digest && !is_legacy) return 0;
    if (has_digest && !reader.read_exact(header.data() + LEGACY_HEADER_SIZE, DIGEST_SIZE)) {
        return 0;
    }

    const std::uint64_t original_size = decode_length(header.data() + 4);
    if (original_size > std::numeric_limits<std::size_t>::max()) return 0;
    const std::uint64_t padding = is_current ? 2 - original_size % 2
                                              : original_size % 2;
    if (original_size > std::numeric_limits<std::uint64_t>::max() - padding) return 0;
    const std::uint64_t encrypted_size = original_size + padding;
    if ((encrypted_size % 2) != 0) return 0;

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> digest_context(
        has_digest ? EVP_MD_CTX_new() : nullptr, EVP_MD_CTX_free);
    if (has_digest && (!digest_context ||
        EVP_DigestInit_ex(digest_context.get(), EVP_sha256(), nullptr) != 1)) return 0;

    std::uint64_t position = 0;
    while (position < encrypted_size) {
        std::array<std::uint8_t, 2> encrypted_pair{};
        std::array<std::uint8_t, 2> plaintext_pair{};
        if (!reader.read_exact(encrypted_pair.data(), encrypted_pair.size())) return 0;
        transform_pair(key.data, encrypted_pair[0], encrypted_pair[1],
                       plaintext_pair.data());
        for (std::size_t index = 0; index < plaintext_pair.size(); ++index) {
            const std::uint64_t byte_position = position + index;
            if (byte_position < original_size) {
                if (has_digest && EVP_DigestUpdate(digest_context.get(),
                        &plaintext_pair[index], 1) != 1) return 0;
                if (!writer.write(&plaintext_pair[index], 1)) return 0;
            } else if (is_current && plaintext_pair[index] != padding) {
                return 0;
            }
        }
        position += encrypted_pair.size();
    }
    if (!reader.at_end()) return 0;
    if (has_digest) {
        std::array<std::uint8_t, DIGEST_SIZE> calculated_digest{};
        unsigned int digest_size = 0;
        if (EVP_DigestFinal_ex(digest_context.get(), calculated_digest.data(),
                               &digest_size) != 1 || digest_size != calculated_digest.size() ||
            !std::equal(calculated_digest.begin(), calculated_digest.end(),
                        header.begin() + LEGACY_HEADER_SIZE)) return 0;
    }
    return writer.finish() ? 1 : 0;
}

const CipherModuleApi API{
    CIPHER_MODULE_ABI_VERSION,
    sizeof(CipherModuleApi),
    ::get_algorithm_info,
    ::get_output_size,
    generate_keys,
    encrypt,
    decrypt,
    free_buffer,
    encrypt_stream,
    decrypt_stream,
    nullptr,
    nullptr,
};

std::size_t output_size(std::size_t input_size, int operation_type) {
    if (operation_type == CIPHER_OPERATION_ENCRYPT) {
        const std::size_t padding = 2 - input_size % 2;
        if (input_size > std::numeric_limits<std::size_t>::max() - padding - HEADER_SIZE) {
            return 0;
        }
        return HEADER_SIZE + input_size + padding;
    }
    if (operation_type == CIPHER_OPERATION_DECRYPT) return input_size;
    return 0;
}

int encrypt_into(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (output == nullptr || (key.data == nullptr && key.size != 0) ||
        (input.data == nullptr && input.size != 0)) return 0;
    const std::size_t required = output_size(input.size, CIPHER_OPERATION_ENCRYPT);
    if (required == 0 || output->data == nullptr || output->size < required) return 0;
    std::uint8_t* temporary = nullptr;
    std::size_t temporary_size = 0;
    if (encrypt_alloc(key.data, key.size, input.data, input.size,
                      &temporary, &temporary_size) == 0) return 0;
    if (temporary_size > output->size) {
        free_buffer_impl(temporary, temporary_size);
        return 0;
    }
    std::memcpy(output->data, temporary, temporary_size);
    output->size = temporary_size;
    free_buffer_impl(temporary, temporary_size);
    return 1;
}

int decrypt_into(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (output == nullptr || (key.data == nullptr && key.size != 0) ||
        input.data == nullptr) return 0;
    const std::size_t required = output_size(input.size, CIPHER_OPERATION_DECRYPT);
    if (required == 0 || (required != 0 && output->data == nullptr) ||
        output->size < required) return 0;
    std::uint8_t* temporary = nullptr;
    std::size_t temporary_size = 0;
    if (decrypt_alloc(key.data, key.size, input.data, input.size,
                      &temporary, &temporary_size) == 0) return 0;
    if (temporary_size > output->size) {
        free_buffer_impl(temporary, temporary_size);
        return 0;
    }
    if (temporary_size != 0) std::memcpy(output->data, temporary, temporary_size);
    output->size = temporary_size;
    free_buffer_impl(temporary, temporary_size);
    return 1;
}

}

extern "C" CIPHER_MODULE_EXPORT const AlgorithmInfo* get_algorithm_info(void) {
    static const AlgorithmInfo INFORMATION{
        CIPHER_MODULE_ABI_VERSION, sizeof(AlgorithmInfo),
        "Шифр Хилла (байтовый вариант)", 4};
    return &INFORMATION;
}

extern "C" CIPHER_MODULE_EXPORT std::size_t get_output_size(
    std::size_t input_size, int operation_type) {
    return output_size(input_size, operation_type);
}

extern "C" CIPHER_MODULE_EXPORT int generate_keys(
    const std::uint8_t* parameters, std::size_t parameters_size,
    std::uint8_t** encryption_key, std::size_t* encryption_key_size,
    std::uint8_t** decryption_key, std::size_t* decryption_key_size) {
    return generate_keys_alloc(parameters, parameters_size, encryption_key,
                               encryption_key_size, decryption_key,
                               decryption_key_size) != 0
        ? CIPHER_MODULE_STATUS_OK : CIPHER_MODULE_STATUS_ERROR;
}

extern "C" CIPHER_MODULE_EXPORT int encrypt(
    ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    return encrypt_into(key, input, output) != 0
        ? CIPHER_MODULE_STATUS_OK : CIPHER_MODULE_STATUS_ERROR;
}

extern "C" CIPHER_MODULE_EXPORT int decrypt(
    ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    return decrypt_into(key, input, output) != 0
        ? CIPHER_MODULE_STATUS_OK : CIPHER_MODULE_STATUS_ERROR;
}

extern "C" CIPHER_MODULE_EXPORT void free_buffer(
    std::uint8_t* buffer, std::size_t buffer_size) {
    free_buffer_impl(buffer, buffer_size);
}

extern "C" CIPHER_MODULE_EXPORT int encrypt_stream(
    ConstBuffer key, std::uint64_t input_size, const std::uint8_t* input_digest,
    CipherReadCallback read_callback, CipherWriteCallback write_callback,
    void* context) {
    try {
        return encrypt_stream_impl(key, input_size, input_digest, read_callback,
                                   write_callback, context) != 0
            ? CIPHER_MODULE_STATUS_OK : CIPHER_MODULE_STATUS_ERROR;
    } catch (...) {
        return CIPHER_MODULE_STATUS_ERROR;
    }
}

extern "C" CIPHER_MODULE_EXPORT int decrypt_stream(
    ConstBuffer key, CipherReadCallback read_callback,
    CipherWriteCallback write_callback, void* context) {
    try {
        return decrypt_stream_impl(key, read_callback, write_callback, context) != 0
            ? CIPHER_MODULE_STATUS_OK : CIPHER_MODULE_STATUS_ERROR;
    } catch (...) {
        return CIPHER_MODULE_STATUS_ERROR;
    }
}

extern "C" CIPHER_MODULE_EXPORT const CipherModuleApi* get_cipher_module_api(void) {
    return &API;
}
