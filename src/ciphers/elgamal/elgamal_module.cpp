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

constexpr std::size_t FIELD_BYTES = 256;
constexpr std::size_t KEY_BYTES = 4 + 3 * FIELD_BYTES;
constexpr std::size_t LEGACY_CONTAINER_HEADER_BYTES = 12;
constexpr std::size_t DIGEST_BYTES = 32;
constexpr std::size_t CONTAINER_HEADER_BYTES = LEGACY_CONTAINER_HEADER_BYTES + DIGEST_BYTES;
constexpr std::size_t PLAINTEXT_BLOCK_BYTES = FIELD_BYTES - 2;
constexpr std::size_t LEGACY_PLAINTEXT_BLOCK_BYTES = FIELD_BYTES - 1;
constexpr std::size_t CIPHERTEXT_BLOCK_BYTES = 2 * FIELD_BYTES;
constexpr std::array<std::uint8_t, 4> PUBLIC_KEY_MAGIC{'E', 'G', 'P', '1'};
constexpr std::array<std::uint8_t, 4> PRIVATE_KEY_MAGIC{'E', 'G', 'S', '1'};
constexpr std::array<std::uint8_t, 4> LEGACY_CIPHERTEXT_MAGIC{'E', 'L', 'G', '1'};
constexpr std::array<std::uint8_t, 4> PREVIOUS_CIPHERTEXT_MAGIC{'E', 'L', 'G', '2'};
constexpr std::array<std::uint8_t, 4> CIPHERTEXT_MAGIC{'E', 'L', 'G', '3'};

struct MemoryWiper {
    void* data;
    std::size_t size;
    ~MemoryWiper() { if (data != nullptr && size != 0) OPENSSL_cleanse(data, size); }
};

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
                      std::array<std::uint8_t, DIGEST_BYTES>& digest) {
    static const std::uint8_t EMPTY_DATA = 0;
    const std::uint8_t* source = size == 0 ? &EMPTY_DATA : data;
    unsigned int digest_size = 0;
    return EVP_Digest(source, size, digest.data(), &digest_size,
                      EVP_sha256(), nullptr) == 1 && digest_size == digest.size();
}

bool append_bn(std::vector<std::uint8_t>& output, const BIGNUM* value) {
    const std::size_t offset = output.size();
    output.resize(offset + FIELD_BYTES);
    return BN_bn2binpad(value, output.data() + offset,
                        static_cast<int>(FIELD_BYTES)) == static_cast<int>(FIELD_BYTES);
}

BnPtr read_bn(const std::uint8_t* input, std::size_t input_size, std::size_t offset) {
    if (input == nullptr || offset > input_size ||
        input_size - offset < FIELD_BYTES) {
        return BnPtr(nullptr);
    }
    return BnPtr(BN_bin2bn(input + offset, static_cast<int>(FIELD_BYTES), nullptr));
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
    if (key == nullptr || key_size != KEY_BYTES ||
        !std::equal(magic.begin(), magic.end(), key)) {
        return false;
    }
    p = read_bn(key, key_size, 4);
    g = read_bn(key, key_size, 4 + FIELD_BYTES);
    third = read_bn(key, key_size, 4 + 2 * FIELD_BYTES);
    if (!p || !g || !third || BN_is_zero(p.get()) || BN_is_zero(g.get()) ||
        BN_is_zero(third.get())) {
        return false;
    }
    if (BN_num_bits(p.get()) != 2048 ||
        BN_cmp(g.get(), BN_value_one()) <= 0 ||
        (magic == PUBLIC_KEY_MAGIC && BN_is_one(third.get()))) {
        return false;
    }
    // Формат ключа использует только группу RFC 3526 с генератором 2.
    BnPtr expected_p(BN_get_rfc3526_prime_2048(nullptr));
    if (!expected_p || BN_cmp(p.get(), expected_p.get()) != 0 || !BN_is_word(g.get(), 2)) {
        return false;
    }
    BnPtr p_minus_one = make_bn();
    if (!p_minus_one || BN_copy(p_minus_one.get(), p.get()) == nullptr ||
        BN_sub_word(p_minus_one.get(), 1) != 1 ||
        BN_cmp(g.get(), p_minus_one.get()) >= 0 ||
        BN_cmp(third.get(), p_minus_one.get()) >= 0) {
        return false;
    }
    if (magic == PUBLIC_KEY_MAGIC) {
        BnPtr subgroup_order(BN_dup(p_minus_one.get()));
        BnPtr check = make_bn();
        BnContextPtr context = make_context();
        if (!subgroup_order || !check || !context ||
            BN_rshift1(subgroup_order.get(), subgroup_order.get()) != 1 ||
            BN_mod_exp(check.get(), third.get(), subgroup_order.get(), p.get(), context.get()) != 1 ||
            !BN_is_one(check.get())) return false;
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
    if ((parameters == nullptr && parameters_size != 0) ||
        (parameters_size != 0 && parameters_size != sizeof(std::uint32_t)) ||
        encryption_key == nullptr ||
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

    bool exponent_ready = false;
    if (parameters_size == 0) {
        exponent_ready = BN_rand_range(private_exponent.get(), range.get()) == 1 &&
                         BN_add_word(private_exponent.get(), 1) == 1;
    } else {
        const std::uint32_t fixed_exponent =
            static_cast<std::uint32_t>(parameters[0]) |
            (static_cast<std::uint32_t>(parameters[1]) << 8) |
            (static_cast<std::uint32_t>(parameters[2]) << 16) |
            (static_cast<std::uint32_t>(parameters[3]) << 24);
        exponent_ready = fixed_exponent > 0 &&
                         BN_set_word(private_exponent.get(), fixed_exponent) == 1 &&
                         BN_cmp(private_exponent.get(), range.get()) <= 0;
    }
    if (!exponent_ready ||
        BN_mod_exp(public_value.get(), generator.get(), private_exponent.get(),
                   p.get(), context.get()) != 1) {
        return 0;
    }

    std::vector<std::uint8_t> public_key(PUBLIC_KEY_MAGIC.begin(), PUBLIC_KEY_MAGIC.end());
    std::vector<std::uint8_t> private_key(PRIVATE_KEY_MAGIC.begin(), PRIVATE_KEY_MAGIC.end());
    VectorWiper private_key_wiper{private_key};
    private_key.reserve(KEY_BYTES);
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
                 std::size_t* output_size,
                 std::uint32_t deterministic_exponent) {
    if (output == nullptr || output_size == nullptr ||
        (input == nullptr && input_size != 0) ||
        input_size > std::numeric_limits<std::uint64_t>::max()) {
        return 0;
    }
    *output = nullptr;
    *output_size = 0;

    BnPtr p(nullptr), generator(nullptr), public_value(nullptr);
    if (!parse_key(key, key_size, PUBLIC_KEY_MAGIC, p, generator, public_value)) {
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

    const std::size_t block_count = input_size / PLAINTEXT_BLOCK_BYTES + 1;
    if (block_count > (std::numeric_limits<std::size_t>::max() - CONTAINER_HEADER_BYTES) /
                          CIPHERTEXT_BLOCK_BYTES) {
        return 0;
    }
    std::vector<std::uint8_t> result(CONTAINER_HEADER_BYTES + block_count * CIPHERTEXT_BLOCK_BYTES);
    std::copy(CIPHERTEXT_MAGIC.begin(), CIPHERTEXT_MAGIC.end(), result.begin());
    encode_length(static_cast<std::uint64_t>(input_size), result.data() + 4);
    std::array<std::uint8_t, DIGEST_BYTES> digest{};
    if (!calculate_digest(input, input_size, digest)) {
        return 0;
    }
    std::copy(digest.begin(), digest.end(), result.begin() + LEGACY_CONTAINER_HEADER_BYTES);

    for (std::size_t block = 0; block < block_count; ++block) {
        const std::size_t offset = block * PLAINTEXT_BLOCK_BYTES;
        const std::size_t block_size = std::min(PLAINTEXT_BLOCK_BYTES, input_size - offset);
        const std::uint8_t padding = static_cast<std::uint8_t>(
            FIELD_BYTES - 1 - block_size);
        std::array<std::uint8_t, FIELD_BYTES> encoded{};
        MemoryWiper encoded_wiper{encoded.data(), encoded.size()};
        encoded[0] = 1;
        if (block_size != 0) {
            std::copy_n(input + offset, block_size, encoded.begin() + 1);
        }
        std::fill(encoded.begin() + static_cast<std::ptrdiff_t>(1 + block_size),
                  encoded.end(), padding);
        const bool exponent_ready = deterministic_exponent == 0
            ? BN_rand_range(ephemeral.get(), range.get()) == 1 &&
              BN_add_word(ephemeral.get(), 1) == 1
            : BN_set_word(ephemeral.get(), deterministic_exponent) == 1 &&
              BN_cmp(ephemeral.get(), range.get()) <= 0;
        if (BN_bin2bn(encoded.data(), static_cast<int>(encoded.size()), message.get()) == nullptr ||
            !exponent_ready ||
            BN_mod_exp(first.get(), generator.get(), ephemeral.get(), p.get(), context.get()) != 1 ||
            BN_mod_exp(shared.get(), public_value.get(), ephemeral.get(), p.get(), context.get()) != 1 ||
            BN_mod_mul(second.get(), message.get(), shared.get(), p.get(), context.get()) != 1) {
            OPENSSL_cleanse(encoded.data(), encoded.size());
            return 0;
        }

        const std::size_t output_offset = CONTAINER_HEADER_BYTES + block * CIPHERTEXT_BLOCK_BYTES;
        if (BN_bn2binpad(first.get(), result.data() + output_offset,
                         static_cast<int>(FIELD_BYTES)) != static_cast<int>(FIELD_BYTES) ||
            BN_bn2binpad(second.get(), result.data() + output_offset + FIELD_BYTES,
                         static_cast<int>(FIELD_BYTES)) != static_cast<int>(FIELD_BYTES)) {
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
        input_size < LEGACY_CONTAINER_HEADER_BYTES ||
        output == nullptr || output_size == nullptr) {
        return 0;
    }
    *output = nullptr;
    *output_size = 0;

    const bool is_current = std::equal(CIPHERTEXT_MAGIC.begin(), CIPHERTEXT_MAGIC.end(), input);
    const bool has_digest = is_current ||
        std::equal(PREVIOUS_CIPHERTEXT_MAGIC.begin(), PREVIOUS_CIPHERTEXT_MAGIC.end(), input);
    if (!has_digest &&
        !std::equal(LEGACY_CIPHERTEXT_MAGIC.begin(), LEGACY_CIPHERTEXT_MAGIC.end(), input)) {
        return 0;
    }
    const std::size_t header_size = has_digest
        ? CONTAINER_HEADER_BYTES
        : LEGACY_CONTAINER_HEADER_BYTES;
    if (input_size < header_size) {
        return 0;
    }

    BnPtr p(nullptr), generator(nullptr), private_exponent(nullptr);
    if (!parse_key(key, key_size, PRIVATE_KEY_MAGIC, p, generator, private_exponent)) {
        return 0;
    }

    const std::uint64_t original_size = decode_length(input + 4);
    if (original_size > std::numeric_limits<std::size_t>::max()) {
        return 0;
    }
    const std::size_t plaintext_size = static_cast<std::size_t>(original_size);
    const std::size_t block_limit = is_current ? PLAINTEXT_BLOCK_BYTES
                                                : LEGACY_PLAINTEXT_BLOCK_BYTES;
    const std::size_t block_count = is_current
        ? plaintext_size / block_limit + 1
        : plaintext_size / block_limit +
          (plaintext_size % block_limit != 0 ? 1 : 0);
    if (block_count > (std::numeric_limits<std::size_t>::max() - header_size) /
                          CIPHERTEXT_BLOCK_BYTES ||
        input_size != header_size + block_count * CIPHERTEXT_BLOCK_BYTES) {
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
        const std::size_t input_offset = header_size + block * CIPHERTEXT_BLOCK_BYTES;
        first = read_bn(input, input_size, input_offset);
        second = read_bn(input, input_size, input_offset + FIELD_BYTES);
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

        std::array<std::uint8_t, FIELD_BYTES> decoded{};
        MemoryWiper decoded_wiper{decoded.data(), decoded.size()};
        if (BN_bn2binpad(message.get(), decoded.data(), static_cast<int>(decoded.size())) !=
                static_cast<int>(decoded.size()) || decoded[0] != 1) {
            OPENSSL_cleanse(decoded.data(), decoded.size());
            return 0;
        }

        const std::size_t offset = block * block_limit;
        const std::size_t block_size = std::min(block_limit, plaintext_size - offset);
        const std::uint8_t expected_padding = static_cast<std::uint8_t>(
            FIELD_BYTES - 1 - block_size);
        const auto is_padding_byte = [is_current, expected_padding](std::uint8_t byte) {
            return is_current ? byte == expected_padding : byte == 0;
        };
        if (!std::all_of(decoded.begin() + static_cast<std::ptrdiff_t>(1 + block_size),
                         decoded.end(), is_padding_byte)) {
            OPENSSL_cleanse(decoded.data(), decoded.size());
            return 0;
        }
        std::copy_n(decoded.begin() + 1, block_size, plaintext.begin() + offset);
        OPENSSL_cleanse(decoded.data(), decoded.size());
    }

    if (has_digest) {
        std::array<std::uint8_t, DIGEST_BYTES> digest{};
        if (!calculate_digest(plaintext.data(), plaintext.size(), digest) ||
            !std::equal(digest.begin(), digest.end(),
                        input + LEGACY_CONTAINER_HEADER_BYTES)) {
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

class StreamReader {
public:
    StreamReader(CipherReadCallback callback, void* context)
        : callback_(callback), context_(context) {}
    ~StreamReader() { OPENSSL_cleanse(buffer_.data(), buffer_.size()); }

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
            const std::size_t chunk = std::min(size - copied, buffer_.size() - buffered_);
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

int encrypt_stream_impl(ConstBuffer key,
                        std::uint64_t input_size,
                        const std::uint8_t* input_digest,
                        CipherReadCallback read_callback,
                        CipherWriteCallback write_callback,
                        void* context,
                        std::uint32_t deterministic_exponent = 0) {
    if (input_digest == nullptr || read_callback == nullptr || write_callback == nullptr ||
        input_size > std::numeric_limits<std::uint64_t>::max() - CONTAINER_HEADER_BYTES) return 0;
    BnPtr p(nullptr), generator(nullptr), public_value(nullptr);
    if (!parse_key(key.data, key.size, PUBLIC_KEY_MAGIC, p, generator, public_value)) return 0;
    BnPtr message = make_bn(), ephemeral = make_bn(), first = make_bn();
    BnPtr shared = make_bn(), second = make_bn(), range = make_bn();
    BnContextPtr context_bn = make_context();
    if (!message || !ephemeral || !first || !shared || !second || !range || !context_bn ||
        BN_copy(range.get(), p.get()) == nullptr || BN_sub_word(range.get(), 2) != 1) return 0;

    StreamReader reader(read_callback, context);
    StreamWriter writer(write_callback, context);
    std::array<std::uint8_t, CONTAINER_HEADER_BYTES> header{};
    std::copy(CIPHERTEXT_MAGIC.begin(), CIPHERTEXT_MAGIC.end(), header.begin());
    encode_length(input_size, header.data() + 4);
    std::copy_n(input_digest, DIGEST_BYTES,
                header.begin() + LEGACY_CONTAINER_HEADER_BYTES);
    if (!writer.write(header.data(), header.size())) return 0;

    std::uint64_t remaining = input_size;
    const std::uint64_t block_count = input_size / PLAINTEXT_BLOCK_BYTES + 1;
    for (std::uint64_t block = 0; block < block_count; ++block) {
        const std::size_t block_size = static_cast<std::size_t>(
            std::min<std::uint64_t>(remaining, PLAINTEXT_BLOCK_BYTES));
        std::array<std::uint8_t, FIELD_BYTES> encoded{};
        MemoryWiper encoded_wiper{encoded.data(), encoded.size()};
        encoded[0] = 1;
        if (block_size != 0 && !reader.read_exact(encoded.data() + 1, block_size)) {
            OPENSSL_cleanse(encoded.data(), encoded.size());
            return 0;
        }
        const std::uint8_t padding = static_cast<std::uint8_t>(FIELD_BYTES - 1 - block_size);
        std::fill(encoded.begin() + static_cast<std::ptrdiff_t>(1 + block_size),
                  encoded.end(), padding);
        const bool exponent_ready = deterministic_exponent == 0
            ? BN_rand_range(ephemeral.get(), range.get()) == 1 &&
              BN_add_word(ephemeral.get(), 1) == 1
            : BN_set_word(ephemeral.get(), deterministic_exponent) == 1 &&
              BN_cmp(ephemeral.get(), range.get()) <= 0;
        if (BN_bin2bn(encoded.data(), static_cast<int>(encoded.size()), message.get()) == nullptr ||
            !exponent_ready ||
            BN_mod_exp(first.get(), generator.get(), ephemeral.get(), p.get(), context_bn.get()) != 1 ||
            BN_mod_exp(shared.get(), public_value.get(), ephemeral.get(), p.get(), context_bn.get()) != 1 ||
            BN_mod_mul(second.get(), message.get(), shared.get(), p.get(), context_bn.get()) != 1) {
            OPENSSL_cleanse(encoded.data(), encoded.size());
            return 0;
        }
        std::array<std::uint8_t, CIPHERTEXT_BLOCK_BYTES> encrypted{};
        const bool encoded_ok =
            BN_bn2binpad(first.get(), encrypted.data(), static_cast<int>(FIELD_BYTES)) ==
                static_cast<int>(FIELD_BYTES) &&
            BN_bn2binpad(second.get(), encrypted.data() + FIELD_BYTES,
                         static_cast<int>(FIELD_BYTES)) == static_cast<int>(FIELD_BYTES);
        OPENSSL_cleanse(encoded.data(), encoded.size());
        if (!encoded_ok || !writer.write(encrypted.data(), encrypted.size())) return 0;
        remaining -= block_size;
    }
    return reader.at_end() && writer.finish() ? 1 : 0;
}

int decrypt_stream_impl(ConstBuffer key,
                        CipherReadCallback read_callback,
                        CipherWriteCallback write_callback,
                        void* context) {
    if (read_callback == nullptr || write_callback == nullptr) return 0;
    BnPtr p(nullptr), generator(nullptr), private_exponent(nullptr);
    if (!parse_key(key.data, key.size, PRIVATE_KEY_MAGIC, p, generator, private_exponent)) return 0;
    StreamReader reader(read_callback, context);
    StreamWriter writer(write_callback, context);
    std::array<std::uint8_t, CONTAINER_HEADER_BYTES> header{};
    if (!reader.read_exact(header.data(), LEGACY_CONTAINER_HEADER_BYTES)) return 0;
    const bool is_current = std::equal(CIPHERTEXT_MAGIC.begin(), CIPHERTEXT_MAGIC.end(), header.begin());
    const bool has_digest = is_current ||
        std::equal(PREVIOUS_CIPHERTEXT_MAGIC.begin(), PREVIOUS_CIPHERTEXT_MAGIC.end(), header.begin());
    const bool is_legacy = std::equal(LEGACY_CIPHERTEXT_MAGIC.begin(), LEGACY_CIPHERTEXT_MAGIC.end(), header.begin());
    if (!has_digest && !is_legacy) return 0;
    if (has_digest && !reader.read_exact(header.data() + LEGACY_CONTAINER_HEADER_BYTES,
                                         DIGEST_BYTES)) return 0;
    const std::uint64_t original_size = decode_length(header.data() + 4);
    const std::uint64_t block_limit = is_current ? PLAINTEXT_BLOCK_BYTES
                                                  : LEGACY_PLAINTEXT_BLOCK_BYTES;
    const std::uint64_t block_count = is_current
        ? original_size / block_limit + 1
        : original_size / block_limit + (original_size % block_limit != 0 ? 1 : 0);
    if (block_count > std::numeric_limits<std::uint64_t>::max() / CIPHERTEXT_BLOCK_BYTES) return 0;
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> digest_context(
        has_digest ? EVP_MD_CTX_new() : nullptr, EVP_MD_CTX_free);
    if (has_digest && (!digest_context ||
        EVP_DigestInit_ex(digest_context.get(), EVP_sha256(), nullptr) != 1)) return 0;
    BnPtr first = make_bn(), second = make_bn(), shared = make_bn();
    BnPtr inverse(nullptr), message = make_bn();
    BnContextPtr bn_context = make_context();
    if (!first || !second || !shared || !message || !bn_context) return 0;

    for (std::uint64_t block = 0; block < block_count; ++block) {
        std::array<std::uint8_t, CIPHERTEXT_BLOCK_BYTES> encrypted{};
        if (!reader.read_exact(encrypted.data(), encrypted.size()) ||
            BN_bin2bn(encrypted.data(), static_cast<int>(FIELD_BYTES), first.get()) == nullptr ||
            BN_bin2bn(encrypted.data() + FIELD_BYTES, static_cast<int>(FIELD_BYTES), second.get()) == nullptr ||
            BN_is_zero(first.get()) || BN_cmp(first.get(), p.get()) >= 0 ||
            BN_cmp(second.get(), p.get()) >= 0 ||
            BN_mod_exp(shared.get(), first.get(), private_exponent.get(), p.get(), bn_context.get()) != 1) return 0;
        inverse.reset(BN_mod_inverse(nullptr, shared.get(), p.get(), bn_context.get()));
        if (!inverse || BN_mod_mul(message.get(), second.get(), inverse.get(), p.get(), bn_context.get()) != 1) return 0;
        std::array<std::uint8_t, FIELD_BYTES> decoded{};
        MemoryWiper decoded_wiper{decoded.data(), decoded.size()};
        if (BN_bn2binpad(message.get(), decoded.data(), static_cast<int>(decoded.size())) !=
                static_cast<int>(decoded.size()) || decoded[0] != 1) {
            OPENSSL_cleanse(decoded.data(), decoded.size());
            return 0;
        }
        const std::uint64_t offset = block * block_limit;
        const std::size_t block_size = static_cast<std::size_t>(
            std::min<std::uint64_t>(block_limit, original_size - offset));
        const std::uint8_t expected_padding = static_cast<std::uint8_t>(FIELD_BYTES - 1 - block_size);
        const auto valid_padding = [is_current, expected_padding](std::uint8_t byte) {
            return is_current ? byte == expected_padding : byte == 0;
        };
        const bool padding_ok = std::all_of(
            decoded.begin() + static_cast<std::ptrdiff_t>(1 + block_size), decoded.end(), valid_padding);
        const bool digest_ok = !has_digest || block_size == 0 ||
            EVP_DigestUpdate(digest_context.get(), decoded.data() + 1, block_size) == 1;
        const bool write_ok = block_size == 0 || writer.write(decoded.data() + 1, block_size);
        OPENSSL_cleanse(decoded.data(), decoded.size());
        if (!padding_ok || !digest_ok || !write_ok) return 0;
    }
    if (!reader.at_end()) return 0;
    if (has_digest) {
        std::array<std::uint8_t, DIGEST_BYTES> digest{};
        unsigned int digest_size = 0;
        if (EVP_DigestFinal_ex(digest_context.get(), digest.data(), &digest_size) != 1 ||
            digest_size != digest.size() || !std::equal(digest.begin(), digest.end(),
                header.begin() + LEGACY_CONTAINER_HEADER_BYTES)) return 0;
    }
    return writer.finish() ? 1 : 0;
}

const CipherModuleApi API{
    CIPHER_MODULE_ABI_VERSION,
    sizeof(CipherModuleApi),
    ::get_algorithm_info,
    ::get_output_size,
    ::generate_keys,
    ::encrypt,
    ::decrypt,
    ::free_buffer,
    ::encrypt_stream,
    ::decrypt_stream,
#ifdef CIPHER_MODULE_TESTING
    ::generate_keys_for_test,
    ::encrypt_for_test,
    ::encrypt_stream_for_test,
#else
    nullptr,
    nullptr,
    nullptr,
#endif
};

std::size_t output_size(std::size_t input_size, int operation_type) {
    if (operation_type == CIPHER_OPERATION_ENCRYPT) {
        const std::size_t block_count = input_size / PLAINTEXT_BLOCK_BYTES + 1;
        if (block_count > (std::numeric_limits<std::size_t>::max() -
                           CONTAINER_HEADER_BYTES) / CIPHERTEXT_BLOCK_BYTES) return 0;
        return CONTAINER_HEADER_BYTES + block_count * CIPHERTEXT_BLOCK_BYTES;
    }
    if (operation_type == CIPHER_OPERATION_DECRYPT) return input_size;
    return 0;
}

int encrypt_into_with_exponent(ConstBuffer key,
                               ConstBuffer input,
                               std::uint32_t deterministic_exponent,
                               MutBuffer* output) noexcept {
    if (output == nullptr || (key.data == nullptr && key.size != 0) ||
        (input.data == nullptr && input.size != 0)) return 0;
    const std::size_t required = output_size(input.size, CIPHER_OPERATION_ENCRYPT);
    if (required == 0 || output->data == nullptr || output->size < required) return 0;
    std::uint8_t* temporary = nullptr;
    std::size_t temporary_size = 0;
    try {
        if (encrypt_impl(key.data, key.size, input.data, input.size,
                         &temporary, &temporary_size,
                         deterministic_exponent) == 0) return 0;
    } catch (...) {
        return 0;
    }
    if (temporary_size > output->size) {
        free_buffer_impl(temporary, temporary_size);
        return 0;
    }
    std::memcpy(output->data, temporary, temporary_size);
    output->size = temporary_size;
    free_buffer_impl(temporary, temporary_size);
    return 1;
}

int encrypt_into(ConstBuffer key, ConstBuffer input, MutBuffer* output) noexcept {
    return encrypt_into_with_exponent(key, input, 0, output);
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

}

extern "C" CIPHER_MODULE_EXPORT const AlgorithmInfo* get_algorithm_info(void) {
    static const AlgorithmInfo INFORMATION{
        CIPHER_MODULE_ABI_VERSION, sizeof(AlgorithmInfo), "Шифр Эль-Гамаля", KEY_BYTES};
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

#ifdef CIPHER_MODULE_TESTING
extern "C" CIPHER_MODULE_EXPORT int generate_keys_for_test(
    const std::uint8_t* parameters, std::size_t parameters_size,
    std::uint8_t** encryption_key, std::size_t* encryption_key_size,
    std::uint8_t** decryption_key, std::size_t* decryption_key_size) {
    try {
        if (parameters == nullptr || parameters_size != sizeof(std::uint32_t)) {
            return CIPHER_MODULE_STATUS_ERROR;
        }
        return generate_keys_impl(parameters, parameters_size, encryption_key,
                                  encryption_key_size, decryption_key,
                                  decryption_key_size) != 0
            ? CIPHER_MODULE_STATUS_OK : CIPHER_MODULE_STATUS_ERROR;
    } catch (...) {
        return CIPHER_MODULE_STATUS_ERROR;
    }
}
#endif

extern "C" CIPHER_MODULE_EXPORT int encrypt(
    ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    return encrypt_into(key, input, output) != 0
        ? CIPHER_MODULE_STATUS_OK : CIPHER_MODULE_STATUS_ERROR;
}

#ifdef CIPHER_MODULE_TESTING
extern "C" CIPHER_MODULE_EXPORT int encrypt_for_test(
    ConstBuffer key, ConstBuffer input, std::uint32_t deterministic_exponent,
    MutBuffer* output) {
    if (deterministic_exponent == 0) return CIPHER_MODULE_STATUS_ERROR;
    return encrypt_into_with_exponent(key, input, deterministic_exponent, output) != 0
        ? CIPHER_MODULE_STATUS_OK : CIPHER_MODULE_STATUS_ERROR;
}
#endif

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

#ifdef CIPHER_MODULE_TESTING
extern "C" CIPHER_MODULE_EXPORT int encrypt_stream_for_test(
    ConstBuffer key, std::uint64_t input_size, const std::uint8_t* input_digest,
    std::uint32_t deterministic_exponent, CipherReadCallback read_callback,
    CipherWriteCallback write_callback, void* context) {
    if (deterministic_exponent == 0) return CIPHER_MODULE_STATUS_ERROR;
    try {
        return encrypt_stream_impl(key, input_size, input_digest, read_callback,
                                   write_callback, context, deterministic_exponent) != 0
            ? CIPHER_MODULE_STATUS_OK : CIPHER_MODULE_STATUS_ERROR;
    } catch (...) {
        return CIPHER_MODULE_STATUS_ERROR;
    }
}
#endif

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
