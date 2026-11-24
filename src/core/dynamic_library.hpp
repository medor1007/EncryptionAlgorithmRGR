#ifndef DYNAMIC_LIBRARY_HPP
#define DYNAMIC_LIBRARY_HPP

#include <string>

class DynamicLibrary {
public:
    DynamicLibrary() = default;
    ~DynamicLibrary();

    DynamicLibrary(const DynamicLibrary&) = delete;
    DynamicLibrary& operator=(const DynamicLibrary&) = delete;

    bool load(const std::string& path, std::string& error);
    void* get_symbol(const std::string& name, std::string& error) const;
    void unload();
    bool is_loaded() const;

private:
    void* handle_ = nullptr;
};

#endif
