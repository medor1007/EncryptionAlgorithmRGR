#include "cipher_module_api.h"

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <vector>

namespace {

constexpr std::size_t kFieldBytes = 256;
constexpr std::size_t kKeyBytes = 4 + 3 * kFieldBytes;
constexpr std::size_t kLegacyContainerHeaderBytes = 12;
constexpr std::size_t kDigestBytes = 32;
constexpr std::size_t kContainerHeaderBytes = kLegacyContainerHeaderBytes + kDigestBytes;
constexpr std::size_t kPlaintextBlockBytes = kFieldBytes - 1;
constexpr std::size_t kCiphertextBlockBytes = 2 * kFieldBytes;
constexpr std::array<std::uint8_t, 4> kPublicKeyMagic{'E', 'G', 'P', '1'};
constexpr std::array<std::uint8_t, 4> kPrivateKeyMagic{'E', 'G', 'S', '1'};
constexpr std::array<std::uint8_t, 4> kLegacyCiphertextMagic{'E', 'L', 'G', '1'};
constexpr std::array<std::uint8_t, 4> kCiphertextMagic{'E', 'L', 'G', '2'};

struct VectorWiper {
    std::vector<std::uint8_t>& bytes;
    ~VectorWiper() {
        if (!bytes.empty()) OPENSSL_cleanse(bytes.data(), bytes.size());
    }
};

struct BnDeleter {
    void operator()(BIGNUM* value) const { BN_clear_free(value); }
};

struct BnContextDeleter {
    void operator()(BN_CTX* value) const { BN_CTX_free(value); }
};

using BnPtr = std::unique_ptr<BIGNUM, BnDeleter>;
using BnContextPtr = std::unique_ptr<BN_CTX, BnContextDeleter>;

BnPtr make_bn() {
    return BnPtr(BN_new());
}

BnContextPtr make_context() {
    return BnContextPtr(BN_CTX_new());
}

bool calculate_digest(const std::uint8_t* data,
                      std::size_t size,
                      std::array<std::uint8_t, kDigestBytes>& digest) {
    static const std::uint8_t empty_data = 0;
    const std::uint8_t* source = size == 0 ? &empty_data : data;
    unsigned int digest_size = 0;
    return EVP_Digest(source, size, digest.data(), &digest_size,
                      EVP_sha256(), nullptr) == 1 && digest_size == digest.size();
}

bool append_bn(std::vector<std::uint8_t>& output, const BIGNUM* value) {
    const std::size_t offset = output.size();
    output.resize(offset + kFieldBytes);
    return BN_bn2binpad(value, output.data() + offset,
                        static_cast<int>(kFieldBytes)) == static_cast<int>(kFieldBytes);
}

BnPtr read_bn(const std::uint8_t* input, std::size_t input_size, std::size_t offset) {
    if (input == nullptr || offset > input_size ||
        input_size - offset < kFieldBytes) {
        return BnPtr(nullptr);
    }
    return BnPtr(BN_bin2bn(input + offset, static_cast<int>(kFieldBytes), nullptr));
}

bool allocate_copy(const std::vector<std::uint8_t>& data, std::uint8_t** output) {
    if (output == nullptr) {
        return false;
    }
    *output = nullptr;
    if (data.empty()) {
        return true;
    }
    auto* buffer = static_cast<std::uint8_t*>(std::malloc(data.size()));
    if (buffer == nullptr) {
        return false;
    }
    std::memcpy(buffer, data.data(), data.size());
    *output = buffer;
    return true;
}

bool parse_key(const std::uint8_t* key,
               std::size_t key_size,
               const std::array<std::uint8_t, 4>& magic,
               BnPtr& p,
               BnPtr& g,
               BnPtr& third) {
    if (key == nullptr || key_size != kKeyBytes ||
        !std::equal(magic.begin(), magic.end(), key)) {
        return false;
    }
    p = read_bn(key, key_size, 4);
    g = read_bn(key, key_size, 4 + kFieldBytes);
    third = read_bn(key, key_size, 4 + 2 * kFieldBytes);
    if (!p || !g || !third || BN_is_zero(p.get()) || BN_is_zero(g.get()) ||
        BN_is_zero(third.get())) {
        return false;
    }
    if (BN_num_bits(p.get()) != 2048 ||
        BN_cmp(g.get(), BN_value_one()) <= 0 ||
        (magic == kPublicKeyMagic && BN_is_one(third.get()))) {
        return false;
    }
    BnPtr p_minus_one = make_bn();
    if (!p_minus_one || BN_copy(p_minus_one.get(), p.get()) == nullptr ||
        BN_sub_word(p_minus_one.get(), 1) != 1 ||
        BN_cmp(g.get(), p_minus_one.get()) >= 0 ||
        BN_cmp(third.get(), p_minus_one.get()) >= 0) {
        return false;
    }
    return true;
}

bool encode_length(std::uint64_t length, std::uint8_t* destination) {
    if (destination == nullptr) {
        return false;
    }
    for (std::size_t i = 0; i < sizeof(length); ++i) {
        destination[i] = static_cast<std::uint8_t>((length >> (8 * i)) & 0xff);
    }
    return true;
}

std::uint64_t decode_length(const std::uint8_t* source) {
    std::uint64_t length = 0;
    for (std::size_t i = 0; i < sizeof(length); ++i) {
        length |= static_cast<std::uint64_t>(source[i]) << (8 * i);
    }
    return length;
}

int generate_keys_impl(const std::uint8_t* parameters,
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

    BnPtr p = make_bn();
    BnPtr generator = make_bn();
    BnPtr private_exponent = make_bn();
    BnPtr public_value = make_bn();
    BnPtr range = make_bn();
    BnContextPtr context = make_context();
    if (!p || !generator || !private_exponent || !public_value || !range || !context) {
        return 0;
    }

    // Стандартная группа RFC 3526: параметры фиксированы, закрытый ключ случаен.
    if (BN_get_rfc3526_prime_2048(p.get()) == nullptr ||
        BN_set_word(generator.get(), 2) != 1 ||
        BN_copy(range.get(), p.get()) == nullptr ||
        BN_sub_word(range.get(), 3) != 1) {
        return 0;
    }

    if (BN_rand_range(private_exponent.get(), range.get()) != 1 ||
        BN_add_word(private_exponent.get(), 1) != 1 ||
        BN_mod_exp(public_value.get(), generator.get(), private_exponent.get(),
                   p.get(), context.get()) != 1) {
        return 0;
    }

    std::vector<std::uint8_t> public_key(kPublicKeyMagic.begin(), kPublicKeyMagic.end());
    std::vector<std::uint8_t> private_key(kPrivateKeyMagic.begin(), kPrivateKeyMagic.end());
    VectorWiper private_key_wiper{private_key};
    if (!append_bn(public_key, p.get()) || !append_bn(public_key, generator.get()) ||
        !append_bn(public_key, public_value.get()) || !append_bn(private_key, p.get()) ||
        !append_bn(private_key, generator.get()) || !append_bn(private_key, private_exponent.get()) ||
        !allocate_copy(public_key, encryption_key) ||
        !allocate_copy(private_key, decryption_key)) {
        std::free(*encryption_key);
        std::free(*decryption_key);
        *encryption_key = nullptr;
        *decryption_key = nullptr;
        return 0;
    }

    *encryption_key_size = public_key.size();
    *decryption_key_size = private_key.size();
    return 1;
}

int encrypt_impl(const std::uint8_t* key,
                 std::size_t key_size,
                 const std::uint8_t* input,
                 std::size_t input_size,
                 std::uint8_t** output,
                 std::size_t* output_size) {
    if (output == nullptr || output_size == nullptr ||
        (input == nullptr && input_size != 0) ||
        input_size > std::numeric_limits<std::uint64_t>::max()) {
        return 0;
    }
    *output = nullptr;
    *output_size = 0;

    BnPtr p(nullptr), generator(nullptr), public_value(nullptr);
    if (!parse_key(key, key_size, kPublicKeyMagic, p, generator, public_value)) {
        return 0;
    }
    BnPtr message = make_bn();
    BnPtr ephemeral = make_bn();
    BnPtr first = make_bn();
    BnPtr shared = make_bn();
    BnPtr second = make_bn();
    BnPtr lower_bound = make_bn();
    BnPtr range = make_bn();
    BnContextPtr context = make_context();
    if (!message || !ephemeral || !first || !shared || !second ||
        !lower_bound || !range || !context ||
        BN_set_word(lower_bound.get(), 1) != 1 ||
        BN_copy(range.get(), p.get()) == nullptr || BN_sub_word(range.get(), 2) != 1) {
        return 0;
    }

    const std::size_t block_count =
        input_size / kPlaintextBlockBytes + (input_size % kPlaintextBlockBytes != 0 ? 1 : 0);
    if (block_count > (std::numeric_limits<std::size_t>::max() - kContainerHeaderBytes) /
                          kCiphertextBlockBytes) {
        return 0;
    }
    std::vector<std::uint8_t> result(kContainerHeaderBytes + block_count * kCiphertextBlockBytes);
    std::copy(kCiphertextMagic.begin(), kCiphertextMagic.end(), result.begin());
    encode_length(static_cast<std::uint64_t>(input_size), result.data() + 4);
    std::array<std::uint8_t, kDigestBytes> digest{};
    if (!calculate_digest(input, input_size, digest)) {
        return 0;
    }
    std::copy(digest.begin(), digest.end(), result.begin() + kLegacyContainerHeaderBytes);

    for (std::size_t block = 0; block < block_count; ++block) {
        const std::size_t offset = block * kPlaintextBlockBytes;
        const std::size_t block_size = std::min(kPlaintextBlockBytes, input_size - offset);
        std::array<std::uint8_t, kFieldBytes> encoded{};
        encoded[0] = 1;
        std::copy_n(input + offset, block_size, encoded.begin() + 1);
        if (BN_bin2bn(encoded.data(), static_cast<int>(encoded.size()), message.get()) == nullptr ||
            BN_rand_range(ephemeral.get(), range.get()) != 1 ||
            BN_add_word(ephemeral.get(), 1) != 1 ||
            BN_mod_exp(first.get(), generator.get(), ephemeral.get(), p.get(), context.get()) != 1 ||
            BN_mod_exp(shared.get(), public_value.get(), ephemeral.get(), p.get(), context.get()) != 1 ||
            BN_mod_mul(second.get(), message.get(), shared.get(), p.get(), context.get()) != 1) {
            OPENSSL_cleanse(encoded.data(), encoded.size());
            return 0;
        }

        const std::size_t output_offset = kContainerHeaderBytes + block * kCiphertextBlockBytes;
        if (BN_bn2binpad(first.get(), result.data() + output_offset,
                         static_cast<int>(kFieldBytes)) != static_cast<int>(kFieldBytes) ||
            BN_bn2binpad(second.get(), result.data() + output_offset + kFieldBytes,
                         static_cast<int>(kFieldBytes)) != static_cast<int>(kFieldBytes)) {
            OPENSSL_cleanse(encoded.data(), encoded.size());
            return 0;
        }
        OPENSSL_cleanse(encoded.data(), encoded.size());
    }

    if (!allocate_copy(result, output)) {
        return 0;
    }
    *output_size = result.size();
    return 1;
}

int decrypt_impl(const std::uint8_t* key,
                 std::size_t key_size,
                 const std::uint8_t* input,
                 std::size_t input_size,
                 std::uint8_t** output,
                 std::size_t* output_size) {
    if (key == nullptr || input == nullptr ||
        input_size < kLegacyContainerHeaderBytes ||
        output == nullptr || output_size == nullptr) {
        return 0;
    }
    *output = nullptr;
    *output_size = 0;

    const bool has_digest = std::equal(kCiphertextMagic.begin(), kCiphertextMagic.end(), input);
    if (!has_digest &&
        !std::equal(kLegacyCiphertextMagic.begin(), kLegacyCiphertextMagic.end(), input)) {
        return 0;
    }
    const std::size_t header_size = has_digest
        ? kContainerHeaderBytes
        : kLegacyContainerHeaderBytes;
    if (input_size < header_size) {
        return 0;
    }

    BnPtr p(nullptr), generator(nullptr), private_exponent(nullptr);
    if (!parse_key(key, key_size, kPrivateKeyMagic, p, generator, private_exponent)) {
        return 0;
    }

    const std::uint64_t original_size = decode_length(input + 4);
    if (original_size > std::numeric_limits<std::size_t>::max()) {
        return 0;
    }
    const std::size_t plaintext_size = static_cast<std::size_t>(original_size);
    const std::size_t block_count =
        plaintext_size / kPlaintextBlockBytes +
        (plaintext_size % kPlaintextBlockBytes != 0 ? 1 : 0);
    if (block_count > (std::numeric_limits<std::size_t>::max() - header_size) /
                          kCiphertextBlockBytes ||
        input_size != header_size + block_count * kCiphertextBlockBytes) {
        return 0;
    }

    BnPtr first(nullptr), second(nullptr), shared(nullptr), inverse(nullptr), message(nullptr);
    BnContextPtr context = make_context();
    if (!context) {
        return 0;
    }

    std::vector<std::uint8_t> plaintext(plaintext_size);
    VectorWiper plaintext_wiper{plaintext};
    for (std::size_t block = 0; block < block_count; ++block) {
        const std::size_t input_offset = header_size + block * kCiphertextBlockBytes;
        first = read_bn(input, input_size, input_offset);
        second = read_bn(input, input_size, input_offset + kFieldBytes);
        shared = make_bn();
        message = make_bn();
        if (!first || !second || !shared || !message || BN_is_zero(first.get()) ||
            BN_cmp(first.get(), p.get()) >= 0 || BN_cmp(second.get(), p.get()) >= 0 ||
            BN_mod_exp(shared.get(), first.get(), private_exponent.get(), p.get(), context.get()) != 1) {
            return 0;
        }

        inverse = BnPtr(BN_mod_inverse(nullptr, shared.get(), p.get(), context.get()));
        if (!inverse || BN_mod_mul(message.get(), second.get(), inverse.get(), p.get(), context.get()) != 1) {
            return 0;
        }

        std::array<std::uint8_t, kFieldBytes> decoded{};
        if (BN_bn2binpad(message.get(), decoded.data(), static_cast<int>(decoded.size())) !=
                static_cast<int>(decoded.size()) || decoded[0] != 1) {
            OPENSSL_cleanse(decoded.data(), decoded.size());
            return 0;
        }

        const std::size_t offset = block * kPlaintextBlockBytes;
        const std::size_t block_size = std::min(kPlaintextBlockBytes, plaintext_size - offset);
        if (!std::all_of(decoded.begin() + 1 + block_size, decoded.end(),
                         [](std::uint8_t byte) { return byte == 0; })) {
            OPENSSL_cleanse(decoded.data(), decoded.size());
            return 0;
        }
        std::copy_n(decoded.begin() + 1, block_size, plaintext.begin() + offset);
        OPENSSL_cleanse(decoded.data(), decoded.size());
    }

    if (has_digest) {
        std::array<std::uint8_t, kDigestBytes> digest{};
        if (!calculate_digest(plaintext.data(), plaintext.size(), digest) ||
            !std::equal(digest.begin(), digest.end(),
                        input + kLegacyContainerHeaderBytes)) {
            return 0;
        }
    }

    if (!allocate_copy(plaintext, output)) {
        return 0;
    }
    *output_size = plaintext.size();
    return 1;
}

int generate_keys_alloc(const std::uint8_t* parameters,
                        std::size_t parameters_size,
                        std::uint8_t** encryption_key,
                        std::size_t* encryption_key_size,
                        std::uint8_t** decryption_key,
                        std::size_t* decryption_key_size) noexcept {
    try {
        return generate_keys_impl(parameters, parameters_size, encryption_key,
                                  encryption_key_size, decryption_key,
                                  decryption_key_size);
    } catch (...) {
        return 0;
    }
}

int encrypt_alloc(const std::uint8_t* key,
                  std::size_t key_size,
                  const std::uint8_t* input,
                  std::size_t input_size,
                  std::uint8_t** output,
                  std::size_t* output_size) noexcept {
    try {
        return encrypt_impl(key, key_size, input, input_size, output, output_size);
    } catch (...) {
        return 0;
    }
}

int decrypt_alloc(const std::uint8_t* key,
                  std::size_t key_size,
                  const std::uint8_t* input,
                  std::size_t input_size,
                  std::uint8_t** output,
                  std::size_t* output_size) noexcept {
    try {
        return decrypt_impl(key, key_size, input, input_size, output, output_size);
    } catch (...) {
        return 0;
    }
}

void free_buffer_impl(std::uint8_t* buffer, std::size_t buffer_size) noexcept {
    if (buffer != nullptr) OPENSSL_cleanse(buffer, buffer_size);
    std::free(buffer);
}

const CipherModuleApi kApi{
    CIPHER_MODULE_ABI_VERSION,
    sizeof(CipherModuleApi),
    ::get_algorithm_info,
    ::get_output_size,
    ::generate_keys,
    ::encrypt,
    ::decrypt,
    ::free_buffer,
};

std::size_t output_size(std::size_t input_size, int operation_type) {
    if (operation_type == CIPHER_OPERATION_ENCRYPT) {
        const std::size_t block_count = input_size / kPlaintextBlockBytes +
            (input_size % kPlaintextBlockBytes != 0 ? 1 : 0);
        if (block_count > (std::numeric_limits<std::size_t>::max() -
                           kContainerHeaderBytes) / kCiphertextBlockBytes) return 0;
        return kContainerHeaderBytes + block_count * kCiphertextBlockBytes;
    }
    if (operation_type == CIPHER_OPERATION_DECRYPT) return input_size;
    return 0;
}

int encrypt_into(ConstBuffer key, ConstBuffer input, MutBuffer* output) noexcept {
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

int decrypt_into(ConstBuffer key, ConstBuffer input, MutBuffer* output) noexcept {
    if (output == nullptr || (key.data == nullptr && key.size != 0) ||
        (input.data == nullptr && input.size != 0)) return 0;
    const std::size_t required = output_size(input.size, CIPHER_OPERATION_DECRYPT);
    if (required != 0 && output->data == nullptr) return 0;
    if (output->size < required) return 0;
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

}  // Анонимное пространство имён.

extern "C" CIPHER_MODULE_EXPORT const AlgorithmInfo* get_algorithm_info(void) {
    static const AlgorithmInfo information{
        CIPHER_MODULE_ABI_VERSION, sizeof(AlgorithmInfo), "Шифр Эль-Гамаля", kKeyBytes};
    return &information;
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
                               decryption_key_size);
}

extern "C" CIPHER_MODULE_EXPORT int encrypt(
    ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    return encrypt_into(key, input, output);
}

extern "C" CIPHER_MODULE_EXPORT int decrypt(
    ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    return decrypt_into(key, input, output);
}

extern "C" CIPHER_MODULE_EXPORT void free_buffer(
    std::uint8_t* buffer, std::size_t buffer_size) {
    free_buffer_impl(buffer, buffer_size);
}

extern "C" CIPHER_MODULE_EXPORT const CipherModuleApi* get_cipher_module_api(void) {
    return &kApi;
}
