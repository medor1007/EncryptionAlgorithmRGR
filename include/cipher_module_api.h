#ifndef CIPHER_MODULE_API_H
#define CIPHER_MODULE_API_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#if defined(CIPHER_MODULE_BUILD)
#define CIPHER_MODULE_EXPORT __declspec(dllexport)
#else
#define CIPHER_MODULE_EXPORT __declspec(dllimport)
#endif
#else
#define CIPHER_MODULE_EXPORT __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define CIPHER_MODULE_ABI_VERSION 1u

typedef struct CipherModuleApi {
    uint32_t abi_version;
    size_t struct_size;
    const char* (*get_name)(void);
    int (*generate_keys)(const uint8_t* parameters,
                         size_t parameters_size,
                         uint8_t** encryption_key,
                         size_t* encryption_key_size,
                         uint8_t** decryption_key,
                         size_t* decryption_key_size);
    int (*encrypt)(const uint8_t* key,
                   size_t key_size,
                   const uint8_t* input,
                   size_t input_size,
                   uint8_t** output,
                   size_t* output_size);
    int (*decrypt)(const uint8_t* key,
                   size_t key_size,
                   const uint8_t* input,
                   size_t input_size,
                   uint8_t** output,
                   size_t* output_size);
    void (*free_buffer)(uint8_t* buffer);
} CipherModuleApi;

typedef const CipherModuleApi* (*GetCipherModuleApi)(void);

CIPHER_MODULE_EXPORT const CipherModuleApi* get_cipher_module_api(void);

#ifdef __cplusplus
}
#endif

#endif
