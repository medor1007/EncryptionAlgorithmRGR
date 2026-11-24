#include "core/cipher_module.hpp"

bool CipherModule::load(const std::string& path, std::string& error) {
    unload();
    if (!library_.load(path, error)) {
        return false;
    }

    void* raw_function = library_.get_symbol("get_cipher_module_api", error);
    if (raw_function == nullptr) {
        library_.unload();
        return false;
    }

    const auto get_api = reinterpret_cast<GetCipherModuleApi>(raw_function);
    api_ = get_api();
    if (api_ == nullptr) {
        error = "Библиотека вернула пустое описание модуля.";
        library_.unload();
        return false;
    }

    if (api_->abi_version != CIPHER_MODULE_ABI_VERSION) {
        error = "Версия интерфейса библиотеки не поддерживается.";
        api_ = nullptr;
        library_.unload();
        return false;
    }

    if (api_->struct_size < sizeof(CipherModuleApi) || api_->get_name == nullptr ||
        api_->generate_keys == nullptr || api_->encrypt == nullptr ||
        api_->decrypt == nullptr || api_->free_buffer == nullptr) {
        error = "Описание библиотеки неполное или несовместимое.";
        api_ = nullptr;
        library_.unload();
        return false;
    }

    error.clear();
    return true;
}

void CipherModule::unload() {
    api_ = nullptr;
    library_.unload();
}

bool CipherModule::is_loaded() const {
    return api_ != nullptr && library_.is_loaded();
}

const char* CipherModule::name() const {
    return is_loaded() ? api_->get_name() : "";
}

const CipherModuleApi* CipherModule::api() const {
    return is_loaded() ? api_ : nullptr;
}
