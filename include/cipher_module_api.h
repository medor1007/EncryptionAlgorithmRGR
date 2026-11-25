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

#define CIPHER_MODULE_ABI_VERSION 2u

typedef struct ConstBuffer {
    const uint8_t* data;
    size_t size;
} ConstBuffer;

typedef struct MutBuffer {
    uint8_t* data;
    size_t size;
} MutBuffer;

typedef struct AlgorithmInfo {
    uint32_t abi_version;
    size_t struct_size;
    const char* algorithm_name;
    size_t key_size;
} AlgorithmInfo;

enum CipherOperation {
    CIPHER_OPERATION_ENCRYPT = 1,
    CIPHER_OPERATION_DECRYPT = 2,
};

typedef struct CipherModuleApi {
    uint32_t abi_version;
    size_t struct_size;
    const AlgorithmInfo* (*get_algorithm_info)(void);
    size_t (*get_output_size)(size_t input_size, int operation_type);
    int (*generate_keys)(const uint8_t* parameters,
                         size_t parameters_size,
                         uint8_t** encryption_key,
                         size_t* encryption_key_size,
                         uint8_t** decryption_key,
                         size_t* decryption_key_size);
    int (*encrypt)(ConstBuffer key, ConstBuffer input, MutBuffer* output);
    int (*decrypt)(ConstBuffer key, ConstBuffer input, MutBuffer* output);
    void (*free_buffer)(uint8_t* buffer, size_t buffer_size);
    int (*generate_keys_for_test)(const uint8_t* parameters,
                                  size_t parameters_size,
                                  uint8_t** encryption_key,
                                  size_t* encryption_key_size,
                                  uint8_t** decryption_key,
                                  size_t* decryption_key_size);
    int (*encrypt_for_test)(ConstBuffer key,
                            ConstBuffer input,
                            uint32_t deterministic_exponent,
                            MutBuffer* output);
} CipherModuleApi;

typedef const CipherModuleApi* (*GetCipherModuleApi)(void);

CIPHER_MODULE_EXPORT const AlgorithmInfo* get_algorithm_info(void);
CIPHER_MODULE_EXPORT size_t get_output_size(size_t input_size, int operation_type);
CIPHER_MODULE_EXPORT int generate_keys(const uint8_t* parameters,
                                      size_t parameters_size,
                                      uint8_t** encryption_key,
                                      size_t* encryption_key_size,
                                      uint8_t** decryption_key,
                                      size_t* decryption_key_size);
CIPHER_MODULE_EXPORT int encrypt(ConstBuffer key,
                                 ConstBuffer input,
                                 MutBuffer* output);
CIPHER_MODULE_EXPORT int decrypt(ConstBuffer key,
                                 ConstBuffer input,
                                 MutBuffer* output);
CIPHER_MODULE_EXPORT void free_buffer(uint8_t* buffer, size_t buffer_size);
#ifdef CIPHER_MODULE_TESTING
CIPHER_MODULE_EXPORT int generate_keys_for_test(const uint8_t* parameters,
                                                size_t parameters_size,
                                                uint8_t** encryption_key,
                                                size_t* encryption_key_size,
                                                uint8_t** decryption_key,
                                                size_t* decryption_key_size);
CIPHER_MODULE_EXPORT int encrypt_for_test(ConstBuffer key,
                                          ConstBuffer input,
                                          uint32_t deterministic_exponent,
                                          MutBuffer* output);
#endif
CIPHER_MODULE_EXPORT const CipherModuleApi* get_cipher_module_api(void);

#ifdef __cplusplus
}
#endif

#endif
