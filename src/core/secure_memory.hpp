#ifndef SECURE_MEMORY_HPP
#define SECURE_MEMORY_HPP

#include <openssl/crypto.h>

#include <cstdint>
#include <memory>
#include <vector>

// Очистка выполняется и при росте контейнера, когда старый буфер освобождается.
template <typename T>
struct SecureAllocator {
    using value_type = T;

    SecureAllocator() = default;
    template <typename U>
    SecureAllocator(const SecureAllocator<U>&) noexcept {}

    T* allocate(std::size_t count) {
        return std::allocator<T>{}.allocate(count);
    }

    void deallocate(T* pointer, std::size_t count) noexcept {
        if (pointer != nullptr) OPENSSL_cleanse(pointer, count * sizeof(T));
        std::allocator<T>{}.deallocate(pointer, count);
    }
};

template <typename T, typename U>
bool operator==(const SecureAllocator<T>&, const SecureAllocator<U>&) noexcept {
    return true;
}

template <typename T, typename U>
bool operator!=(const SecureAllocator<T>&, const SecureAllocator<U>&) noexcept {
    return false;
}

using SecureBytes = std::vector<std::uint8_t, SecureAllocator<std::uint8_t>>;

#endif
