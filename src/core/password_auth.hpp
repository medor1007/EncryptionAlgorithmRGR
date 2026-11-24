#ifndef PASSWORD_AUTH_HPP
#define PASSWORD_AUTH_HPP

#include <filesystem>
#include <string>

bool create_password_record(const std::filesystem::path& path,
                            const std::string& password,
                            std::string& error);
bool verify_password_record(const std::filesystem::path& path,
                            const std::string& password,
                            std::string& error);
bool authenticate_user();

#endif
