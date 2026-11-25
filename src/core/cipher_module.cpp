#include "core/cipher_module.hpp"

#include <type_traits>

// Загрузка библиотеки и проверка доступности функций общего интерфейса.
bool CipherModule::load(const std::string& path, std::string& error) {
    unload();
    if (!library_.load(path, error)) {
        return false;
    }

    const auto load_function = [this, &error](const char* name, auto& function) {
        void* raw_function = library_.get_symbol(name, error);
        if (raw_function == nullptr) return false;
        function = reinterpret_cast<std::decay_t<decltype(function)>>(raw_function);
        return true;
    };
    if (!load_function("get_algorithm_info", api_storage_.get_algorithm_info) ||
        !load_function("get_output_size", api_storage_.get_output_size) ||
        !load_function("generate_keys", api_storage_.generate_keys) ||
        !load_function("encrypt", api_storage_.encrypt) ||
        !load_function("decrypt", api_storage_.decrypt) ||
        !load_function("free_buffer", api_storage_.free_buffer) ||
        !load_function("encrypt_stream", api_storage_.encrypt_stream) ||
        !load_function("decrypt_stream", api_storage_.decrypt_stream)) {
        library_.unload();
        api_storage_ = {};
        return false;
    }
    api_storage_.abi_version = CIPHER_MODULE_ABI_VERSION;
    api_storage_.struct_size = sizeof(CipherModuleApi);
    std::string optional_error;
    void* test_key_function = library_.get_symbol("generate_keys_for_test", optional_error);
    if (test_key_function != nullptr) {
        api_storage_.generate_keys_for_test =
            reinterpret_cast<decltype(api_storage_.generate_keys_for_test)>(test_key_function);
    }
    optional_error.clear();
    void* test_encrypt_function = library_.get_symbol("encrypt_for_test", optional_error);
    if (test_encrypt_function != nullptr) {
        api_storage_.encrypt_for_test =
            reinterpret_cast<decltype(api_storage_.encrypt_for_test)>(test_encrypt_function);
    }
    api_ = &api_storage_;

    const AlgorithmInfo* information = api_->get_algorithm_info();
    if (information == nullptr || information->abi_version != CIPHER_MODULE_ABI_VERSION ||
        information->struct_size < sizeof(AlgorithmInfo) ||
        information->algorithm_name == nullptr || information->key_size == 0) {
        error = "Библиотека вернула некорректные метаданные алгоритма.";
        api_ = nullptr;
        library_.unload();
        return false;
    }

    error.clear();
    return true;
}

void CipherModule::unload() {
    api_ = nullptr;
    api_storage_ = {};
    library_.unload();
}

bool CipherModule::is_loaded() const {
    return api_ != nullptr && library_.is_loaded();
}

const char* CipherModule::name() const {
    if (!is_loaded()) return "";
    const AlgorithmInfo* information = api_->get_algorithm_info();
    return information == nullptr ? "" : information->algorithm_name;
}

const CipherModuleApi* CipherModule::api() const {
    return is_loaded() ? api_ : nullptr;
}
