#include "core/dynamic_library.hpp"

#include <sstream>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

DynamicLibrary::~DynamicLibrary() {
    unload();
}

bool DynamicLibrary::load(const std::string& path, std::string& error) {
    unload();

#ifdef _WIN32
    handle_ = reinterpret_cast<void*>(LoadLibraryA(path.c_str()));
    if (handle_ == nullptr) {
        error = "Не удалось загрузить библиотеку «" + path + "» (код " +
                std::to_string(GetLastError()) + ").";
        return false;
    }
#else
    dlerror();
    handle_ = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (handle_ == nullptr) {
        const char* detail = dlerror();
        error = "Не удалось загрузить библиотеку «" + path + "»: " +
                (detail == nullptr ? "неизвестная ошибка" : detail);
        return false;
    }
#endif

    error.clear();
    return true;
}

void* DynamicLibrary::get_symbol(const std::string& name, std::string& error) const {
    if (handle_ == nullptr) {
        error = "Библиотека не загружена.";
        return nullptr;
    }

#ifdef _WIN32
    auto* symbol = reinterpret_cast<void*>(GetProcAddress(
        reinterpret_cast<HMODULE>(handle_), name.c_str()));
    if (symbol == nullptr) {
        error = "В библиотеке не найдена функция «" + name +
                "» (код " + std::to_string(GetLastError()) + ").";
        return nullptr;
    }
#else
    dlerror();
    void* symbol = dlsym(handle_, name.c_str());
    const char* detail = dlerror();
    if (detail != nullptr) {
        error = "В библиотеке не найдена функция «" + name + "»: " + detail;
        return nullptr;
    }
#endif

    error.clear();
    return symbol;
}

void DynamicLibrary::unload() {
    if (handle_ == nullptr) {
        return;
    }

#ifdef _WIN32
    FreeLibrary(reinterpret_cast<HMODULE>(handle_));
#else
    dlclose(handle_);
#endif

    handle_ = nullptr;
}

bool DynamicLibrary::is_loaded() const {
    return handle_ != nullptr;
}
