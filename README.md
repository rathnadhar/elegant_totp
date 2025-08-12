# elegant_totp

A production‑grade, header‑only C++23 library for Time‑based One‑Time Passwords (TOTP),  
designed with **strong typing**, **monadic error handling**, and **expressive API design**.

---

## ✨ Features
1. RFC 6238 compliant TOTP generation
2. Strict RFC 4648 Base32 decoding
3. Strongly typed time & key abstractions
4. Header‑only, dependency‑light design
5. Ninja‑friendly CMake install semantics
6. Audit‑friendly code layout & naming

---

## 📦 Installation

```bash
git clone git@github.com:rathnadhar/elegant_totp.git
cd elegant_totp
cmake -B build -GNinja
ninja -C build install
```

## Dependency

**elegant_totp** depends on [`elegant_exception`](https://github.com/rathnadhar/elegant_exception) for its expressive, audit-friendly error handling.

If you consume **elegant_totp** via CMake’s `find_package`,  
`elegant_exception` is brought in automatically as a transitive dependency —  
no manual setup is required.

If you prefer to integrate manually, ensure `elegant_exception` is available and its target  
`elegant_exception::elegant_exception` is visible to your project.

> This choice of dependency reflects our design principle: every error path is explicit,  
> every exception type intentional.

## 🚀 Usage

```c++
#include <elegant_totp/totp.hpp>

int main()
{
    using namespace elegant_totp;   

    //First set up the TOTP configuration
    config_options cfg
    {
        .step   = std::chrono::seconds{30},
        .t0     = std::chrono::sys_seconds{std::chrono::seconds{0}},
        .digits = 6,
        .skew   = 1,
        .alg    = hash_alg::sha1
    };
    
    elegant_totp totp{cfg};
    
    //TOTP generation
    totp.generate("JBSWY3DPEHPK3PXP",std::chrono::system_clock::now())
    .and_then([&](const uint32_t generated_totp) -> std::expected<void, elegant_exception>
    {
        std::cout << totp.to_string(generated_totp) << std::endl;        
        return{};
    })
    .or_else([](const elegant_exception::elegant_exception& cex)  -> std::expected<void, elegant_exception>
    {
        std::cerr << cex.what() << std::endl;   
        return std::unexpected{cex};
    });     

    //Verfiy TOTP
    std::string user_code = "123456"; //TOTP to be verified
    
    totp.verify(user_code, key, std::chrono::system_clock::now())
    .and_then([]() -> std::expected<void, elegant_exception>
    {
        std::cout << "✅ Code verified\n";
        return {};
    })
    .or_else([](const elegant_exception& cex) -> std::expected<void, elegant_exception>
    {
        std::cerr << cex.what() << std::endl;
        return std::unexpected{cex};
    });     
    
    return 0;
}
```

## 📜 License

MIT This project is licensed under the MIT License — a permissive license that allows reuse with minimal restrictions.

## 👤 Author

### Rathnadhar K V

Passionate about modern C++ design, monadic error handling, and building elegant, dependency-light libraries.

GitHub: @rathnadhar

