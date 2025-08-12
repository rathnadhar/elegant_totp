cmake_minimum_required(VERSION 3.25)

project(elegant_totp
    VERSION 1.0.0
    LANGUAGES CXX
)

# 🧠 Enforce modern C++23
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 📍 Default install prefix (can be overridden)
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "/usr/local" CACHE PATH "Install path prefix" FORCE)
endif()

# 📁 Header-only library
add_library(elegant_totp INTERFACE)

target_include_directories(elegant_totp INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# 📤 Install headers to /usr/local/include/elegant_totp
install(
    DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
    DESTINATION include/elegant_totp
    FILES_MATCHING PATTERN "*.h"
                   PATTERN "*.hpp"
)

# 📦 Install target and config
install(
    TARGETS elegant_totp
    EXPORT elegant_totp_targets
)

install(
    EXPORT elegant_totp_targets
    FILE elegant_totpConfig.cmake
    NAMESPACE elegant_totp::
    DESTINATION lib/cmake/elegant_totp
)

# 📄 Install license
install(
    FILES LICENSE
    DESTINATION share/elegant_totp
)
