#ifndef CIPHER_MODULE_HPP
#define CIPHER_MODULE_HPP

#include "cipher_module_api.h"
#include "core/dynamic_library.hpp"

#include <string>

class CipherModule {
public:
    CipherModule() = default;
    ~CipherModule() = default;

    CipherModule(const CipherModule&) = delete;
    CipherModule& operator=(const CipherModule&) = delete;

    bool load(const std::string& path, std::string& error);
    void unload();
    bool is_loaded() const;
    const char* name() const;
    const CipherModuleApi* api() const;

private:
    DynamicLibrary library_;
    CipherModuleApi api_storage_{};
    const CipherModuleApi* api_ = nullptr;
};

#endif
