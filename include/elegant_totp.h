//
//                   Shree Matraye Namaha
//                   --------------------
// elegant_totp - C++ Generic TOTP generator/verifier Class Library
//
// Copyright (c) 2025 Rathnadhar K V (Rathnadhar Research RR-->)
//
// Licensed under the MIT License.
// You may obtain a copy of the License at: https://opensource.org/licenses/MIT
//
// This software is provided "as is", without warranty of any kind, express or implied.
// See the License for the specific language governing permissions and limitations.

#pragma once

#include <array>
#include <string>
#include <string_view>
#include <chrono>
#include <expected>
#include <cstdint>
#include <bit>
#include <algorithm>
#include <vector>
#include <cmath>
#include <stdexcept>
#include <cctype>
#include <ranges>
#include <span>
#include <elegant_exception/elegant_exception.h>

using time_point = std::chrono::system_clock::time_point;
using raw_bytes = std::vector<std::uint8_t>;

template<typename Tag>
struct strong_buffer
{
    raw_bytes data;

    explicit strong_buffer(raw_bytes d) : data(std::move(d)) {}
    operator std::span<std::uint8_t const>() const { return data; }
};

struct secret_key_tag {};
struct byte_buffer_tag {};

using secret_key = strong_buffer<secret_key_tag>;
using byte_buffer = strong_buffer<byte_buffer_tag>;

namespace elegant_otp::elegant_totp
{
    enum class hash_alg
    {
        sha1,
        sha256,
        sha512
    };

    enum elegant_totp_error_id : ExceptionID
    {
      INVALID_BASE32 = 1,
      EMPTY_SECRET,
      UNSUPPORTED_ALGORITHM,
      INVALID_DIGITS,
      INTERNAL_ERROR
    };

    constexpr std::array<std::uint32_t, 5> initial_hash{0x67452301u,
                                                        0xEFCDAB89u,
                                                        0x98BADCFEu,
                                                        0x10325476u,
                                                        0xC3D2E1F0u
                                                       };

    //This table has to be created anyhow for base32_decoding... why not get it
    //implemented at compile time itself
    constexpr std::array<uint8_t, 256> base32_decode_table =
    {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };

    constexpr std::array<char, 32> base32_encode_table =
    {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z', '2', '3', '4', '5', '6', '7'
    };

    // Optional: helper to build your elegant_exception consistently
    inline auto make_exception = [](elegant_totp_error_id in_elegant_totp_error_id,
                                    std::string_view      in_error_message
                                   ) -> elegant_exception::elegant_exception
    {
        return elegant_exception::elegant_exception{static_cast<ExceptionID>(in_elegant_totp_error_id),
                                                    in_error_message
                                                   };
    };

    // Optional: clearer round-up than bit-hack reserve, if you prefer readability.
    inline auto round_up_to_64 = [](std::size_t n)  noexcept ->  std::size_t
                                 {
                                    constexpr std::size_t block{64u};
                                    constexpr std::size_t sha_padding_size{sizeof(std::uint8_t) /*0x80*/ +
                                                                           sizeof(std::uint64_t)
                                                                          }; /*message length*/
                                    const std::size_t need{(n + sha_padding_size)};

                                    // Optional overflow guard (pick policy you prefer)
                                    if (need < n) [[unlikely]]
                                    {
                                        return std::numeric_limits<std::size_t>::max();
                                    }

                                    return ((need + (block - 1)) / block) * block;
                                 };

    inline auto store_be32 = [](std::span<std::uint8_t, 4> out, std::uint32_t v) noexcept ->  void
                                {
                                   out[0] = static_cast<std::uint8_t>((v >> 24) & 0xFF);
                                   out[1] = static_cast<std::uint8_t>((v >> 16) & 0xFF);
                                   out[2] = static_cast<std::uint8_t>((v >>  8) & 0xFF);
                                   out[3] = static_cast<std::uint8_t>( v        & 0xFF);
                                };

    inline constexpr auto load_be32 = [](std::span<const std::uint8_t, 4> in) noexcept -> std::uint32_t
                                {
                                    return (static_cast<std::uint32_t>(in[0]) << 24)
                                        | (static_cast<std::uint32_t>(in[1]) << 16)
                                        | (static_cast<std::uint32_t>(in[2]) <<  8)
                                        | (static_cast<std::uint32_t>(in[3]));
                                };


    // 256 won't fit in uint8_t; use size_t (or uint16_t/unsigned) instead
    inline constexpr std::size_t base32_array_size{256};

    class elegant_totp
    {
        private:
            inline static constexpr size_t  block_size{64};

            int      digits{};
            int      period{};
            int      skew{};
            hash_alg algorithm{};

            std::expected<std::vector<char>, elegant_exception::elegant_exception> validate_base32_symbols(std::string_view input) const
            {
                auto filtered = input
                                | std::views::filter([](char c)
                                 {
                                     return c != '=' && c != ' ' && c != '\n' && c != '\r' && c != '\t';
                                 })
                                | std::views::transform([](char c) -> std::expected<char, elegant_exception::elegant_exception>
                                 {
                                     const char upper = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                                     const auto val = base32_decode_table[static_cast<std::uint8_t>(upper)];

                                     if (val == 0xFF)
                                     {
                                         inline static constexpr std::string_view invalid_base32_character_,essage{"Invalid base32 character: '{}' in input"};
                                         return(std::unexpected(make_exception(INVALID_BASE32,
                                                                               std::format(invalid_base32_character_message,upper)
                                                                              )
                                                               )
                                                );
                                     }

                                     return upper;
                                 });

                auto it = std::ranges::find_if(filtered | views::enumerate, [](auto pair)
                {
                    return !pair.second;
                });

                if (it != std::ranges::end(filtered))
                {
                    const auto [pos, maybe_char] = *it;
                    return std::unexpected(maybe_char.error());
                }

                // Collect validated characters
                return std::ranges::to<std::vector<char>>(filtered | std::views::transform([](auto&& e) { return *e; }));
            }

            // Decode base32 string to bytes
            std::expected<byte_buffer, elegant_exception::elegant_exception> base32_decode(std::string_view input) const
            {
                // Validate input
                return  validate_base32_symbols(input)
                        .and_then([&](const byte_buffer& validated)
                        {
                            const auto& symbols = *validated;
                            const size_t symbol_count = validated.size();
                            if (symbol_count == 0)
                            {
                                return byte_buffer{}; // empty input
                            }

                            // Each 8 symbols = 5 bytes
                            const size_t full_blocks = symbol_count / 8;
                            const size_t remainder = symbol_count % 8;

                            byte_buffer output;
                            output.reserve(full_blocks * 5);

                            auto decode_symbol = [](char c) -> uint8_t
                            {
                                return base32_decode_table[static_cast<std::uint8_t>(c)];
                            };

                            auto decode_block = [&](auto begin)
                            {
                                const uint8_t s0 = decode_symbol(begin[0]);
                                const uint8_t s1 = decode_symbol(begin[1]);
                                const uint8_t s2 = decode_symbol(begin[2]);
                                const uint8_t s3 = decode_symbol(begin[3]);
                                const uint8_t s4 = decode_symbol(begin[4]);
                                const uint8_t s5 = decode_symbol(begin[5]);
                                const uint8_t s6 = decode_symbol(begin[6]);
                                const uint8_t s7 = decode_symbol(begin[7]);

                                output.push_back((s0 << 3) | (s1 >> 2));
                                output.push_back((s1 << 6) | (s2 << 1) | (s3 >> 4));
                                output.push_back((s3 << 4) | (s4 >> 1));
                                output.push_back((s4 << 7) | (s5 << 2) | (s6 >> 3));
                                output.push_back((s6 << 5) | s7);
                            };

                            size_t index{};

                            while(index < full_blocks)
                            {
                                decode_block(&symbols[index * 8]);
                                ++index;
                            }

                            if (remainder > 0)
                            {
                                std::array<char, 8> padded{};
                                std::ranges::copy(symbols | std::views::drop(full_blocks * 8), padded.begin());
                                std::fill(padded.begin() + remainder, padded.end(), 'A'); // 'A' decodes to 0

                                // Decode padded block
                                std::uint32_t buffer{};
                                std::size_t bits{};

                                for (char c : padded)
                                {
                                    const auto val = base32_decode_table[static_cast<std::uint8_t>(c)];
                                    buffer = (buffer << 5) | val;
                                    bits += 5;
                                }

                                // Strict trailing-bit check: any leftover bits must be zero (RFC 4648 §6)
                                if (bits != 40)
                                {
                                    const std::uint32_t mask = (1u << (40 - bits)) - 1u;
                                    if ((buffer & mask) != 0)
                                    {
                                        inline static constexpr std::string_view invalid_trailing_bits_message{"Invalid trailing bits in base32 input"};
                                        return(std::unexpected(make_exception(INVALID_BASE32,
                                                                              invalid_trailing_bits_message
                                                                             )
                                                               )
                                              );
                                    }
                                }

                                // Extract bytes from buffer
                                std::size_t expected_bytes = full_blocks * 5 + output_sizes[remainder];

                                index = 0;
                                while(index < output_sizes[remainder])
                                {
                                    output.push_back(static_cast<uint8_t>(buffer >> ((output_sizes[remainder] - 1 - index) * 8)));
                                    ++index;
                                }

                                // Consistency check: output size must match expected
                                if (output.size() != expected_bytes)
                                {
                                    inline static constexpr std::string_view invalid_base32_message{"Invalid base32 length/padding"};
                                    return(std::unexpected(make_exception(INVALID_BASE32,
                                                                          invalid_base32_message
                                                                         )
                                                           )
                                           );
                                }
                            }

                            return output;
                        })
                        .or_else([](const elegant_exception::elegant_exception cex)
                        {
                            return(std::unexpected(cex));
                        });
            }

            std::array<std::uint8_t, 20> sha1(std::span<const std::uint8_t> input) const
            {
                using namespace std::views;

                // Step 1: Pad the input
                const std::uint64_t bit_length = static_cast<std::uint64_t>(input.size()) * 8;

                raw_bytes padded;
                padded.reserve(round_up_to_64(input.size()));

                std::ranges::copy(input, std::back_inserter(padded));
                padded.push_back(0x80);

                while ((padded.size() % 64) != 56)
                {
                    padded.push_back(0x00);
                }

                // Append big-endian 64-bit length
                auto length_bytes = std::views::iota(0, 8)
                                    | std::views::transform([=](int i)
                                        {
                                            return static_cast<std::uint8_t>((bit_length >> ((7 - i) * 8)) & 0xFF);
                                        });

                std::ranges::copy(length_bytes, std::back_inserter(padded));

                // Step 2: Initialize hash state
                std::array<std::uint32_t, 5> hash_register = initial_hash;

                //universal tracker!
                std::size_t index{};

                // Step 3: Process each 512-bit chunk
                for (auto&& blck : padded | chunk(64))
                {
                    std::array<std::uint32_t, 80> w{};
                    index = 0;

                    // w[0..15]: big-endian words (iterator-safe)
                    auto base = std::ranges::begin(blck);

                    // w[0..15]: big-endian 32-bit words from the chunk
                    while(index < 16)
                    {
                        w[index] = load_be32(base + index * 4);
                        ++index;
                    }

                    // w[16..79]
                    index = 16;
                    while(index < 80)
                    {
                        w[index] = std::rotl(w[index - 3] ^ w[index - 8] ^ w[index - 14] ^ w[index - 16], 1);
                        ++index;
                    }

                    std::uint32_t a{hash_register[0]};
                    std::uint32_t b{hash_register[1]};
                    std::uint32_t c{hash_register[2]};
                    std::uint32_t d{hash_register[3]};
                    std::uint32_t e{hash_register[4]};

                    index = 0;
                    while (index < 80)
                    {
                        std::uint32_t f{};
                        std::uint32_t k{};

                        if (index < 20)
                        {
                            f = (b & c) | ((~b) & d);
                            k = 0x5A827999u;
                        }
                        else if (index < 40)
                        {
                            f = b ^ c ^ d;
                            k = 0x6ED9EBA1u;
                        }
                        else if (index < 60)
                        {
                            f = (b & c) | (b & d) | (c & d);
                            k = 0x8F1BBCDCu;
                        }
                        else
                        {
                            f = b ^ c ^ d;
                            k = 0xCA62C1D6u;
                        }

                        std::uint32_t temp = std::rotl(a, 5) + f + e + k + w[index];
                        e = d;
                        d = c;
                        c = std::rotl(b, 30);
                        b = a;
                        a = temp;

                        ++index;
                    }

                    hash_register[0] += a;
                    hash_register[1] += b;
                    hash_register[2] += c;
                    hash_register[3] += d;
                    hash_register[4] += e;
                }

                // Step 4: Produce final digest
                std::array<std::uint8_t, 20> digest;
                index = 0;
                while(index < 5)
                {
                    sha1_detail::store_be32(digest.data() + index * 4, hash_register[index]);
                    ++index;
                }

                return digest;
            }

            // HMAC-SHA1 using strong secret_key and generic message span
            std::array<std::uint8_t, 20> hmac_sha1(const secret_key& key, std::span<const std::uint8_t> message) const
            {
                // Step 1: Normalize key to block_size
                raw_bytes key_block;

                {
                    auto k = std::span{key};

                    if (k.size() > block_size)
                    {
                        auto hashed = sha1(k); // 20 bytes
                        std::ranges::copy(hashed, std::back_inserter(key_block));
                    }
                    else
                    {
                        std::ranges::copy(k, std::back_inserter(key_block));
                    }

                    key_block.resize(block_size, 0x00);
                }

                // Step 2: Build inner and outer pads
                std::array<std::uint8_t, block_size> ipad{};
                std::array<std::uint8_t, block_size> opad{};

                std::size_t index{};

                while (index < block_size)
                {
                    const auto b = key_block[index];
                    ipad[index] = static_cast<std::uint8_t>(b ^ 0x36);
                    opad[index] = static_cast<std::uint8_t>(b ^ 0x5C);
                    ++index;
                }

                // Step 3: inner = SHA1(ipad || message)
                raw_bytes inner_data;
                inner_data.reserve(block_size + message.size());

                std::ranges::copy(ipad, std::back_inserter(inner_data));
                std::ranges::copy(message, std::back_inserter(inner_data));

                auto inner_hash = sha1(inner_data);

                // Step 4: outer = SHA1(opad || inner_hash)
                raw_bytes outer_data;
                outer_data.reserve(block_size + inner_hash.size());

                std::ranges::copy(opad, std::back_inserter(outer_data));
                std::ranges::copy(inner_hash, std::back_inserter(outer_data));

                return sha1(outer_data);
            }

            std::expected<std::vector<uint8_t>, elegant_exception::elegant_exception> compute_hmac(const std::vector<uint8_t>& key,
                                                                                                   const std::array<uint8_t, 8>& message
                                                                                                  ) const
            {
                switch (algorithm)
                {
                    case hash_alg::sha1:   return hmac_sha1(key, message);
                    case hash_alg::sha256: return hmac_sha256(key, message);
                    case hash_alg::sha512: return hmac_sha512(key, message);
                    default:
                    {
                        inline static constexpr std::string_view unsupported_algorithm_message{"Unsupported hash algorithm in elegant_totp::compute_hmac"};
                        return(std::unexpected(make_exception(UNSUPPORTED_ALGORITHM,
                                                              unsupported_algorithm_message
                                                             )
                                              )
                               );
                    }
                }
            }

        public:
            struct config_options
            {
                std::chrono::seconds     step{std::chrono::seconds{30}};
                std::chrono::sys_seconds t0{}; // epoch
                int                      digits{6};
                int                      skew{1};
                hash_alg                 alg{hash_alg::sha1};
            };

            explicit elegant_totp(config_options in_options) noexcept
                : digits{in_options.digits},
                  period{in_options.step.count()},
                  skew{in_options.skew},
                  algorithm{in_options.alg}
            {
            }

            [[nodiscard]]
            int get_digits() const noexcept
            {
                return(digits);
            }

            [[nodiscard]]
            int get_period() const noexcept
            {
                return(period);
            }

            [[nodiscard]]
            int get_skew() const noexcept
            {
                return(skew);
            }

            [[nodiscard]]
            hash_alg get_algorithm() const noexcept
            {
                return(algorithm);
            }

            [[nodiscard]]
            std::expected<uint32_t, elegant_exception::elegant_exception> generate(std::string_view base32_secret,
                                                                                   std::chrono::system_clock::time_point tp
                                                                                  )
            {
                const std::uint64_t counter = std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count() / period;

                std::array<uint8_t, 8> counter_bytes{};

                std::ranges::copy(std::views::iota(0, 8)
                                  | std::views::transform([counter](int i)
                                    {
                                        const int shift = (7 - i) * 8;
                                        return static_cast<uint8_t>((counter >> shift) & 0xFF);
                                    }),
                                    counter_bytes.begin()
                                );

                return base32_decode(base32_secret)
                    .and_then([&](const std::vector<uint8_t>& decoded)
                    {
                        return compute_hmac(decoded, counter_bytes);
                    })
                    .transform([&](const std::vector<uint8_t>& hmac)
                    {
                        const int offset = hmac[19] & 0x0F;

                        const uint32_t binary =
                            ((hmac[offset]     & 0x7F) << 24) |
                            ((hmac[offset + 1] & 0xFF) << 16) |
                            ((hmac[offset + 2] & 0xFF) << 8)  |
                            ( hmac[offset + 3] & 0xFF);

                        const uint32_t modulus =
                            std::ranges::fold_left(std::views::iota(0, digits), 1u,
                                                   [](uint32_t acc, int)
                                                   {
                                                       return acc * 10;
                                                   });

                        return(binary % modulus);
                    });
            }

            [[nodiscard]]
            std::expected<bool, elegant_exception::elegant_exception> verify(std::string_view base32_secret,
                                                                             uint32_t candidate,
                                                                             time_point tp = std::chrono::system_clock::now()
                                                                            ) const
            {
                const std::int64_t base_counter =
                    std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count() / period;

                const uint32_t modulus = std::ranges::fold_left(std::views::iota(0, digits), 1u,
                                                                [](uint32_t acc, int)
                                                                {
                                                                    return acc * 10;
                                                                });

                return base32_decode(base32_secret)
                    .transform([&](const std::vector<uint8_t>& decoded)
                    {
                        return std::ranges::any_of(
                            std::views::iota(-skew, skew + 1),
                            [&](int delta)
                            {
                                const std::uint64_t counter = static_cast<std::uint64_t>(base_counter + delta);

                                std::array<uint8_t, 8> counter_bytes{};
                                std::ranges::copy(std::views::iota(0, 8)
                                                  | std::views::transform([counter](int i)
                                                  {
                                                      const int shift = (7 - i) * 8;
                                                      return static_cast<uint8_t>((counter >> shift) & 0xFF);
                                                  }),
                                                  counter_bytes.begin()
                                                );

                                compute_hmac(decoded, counter_bytes)
                                .and_then([&](const std::vector<uint8_t>& hmac)
                                {
                                    const int offset = hmac[19] & 0x0F;

                                    const uint32_t binary = ((hmac[offset]     & 0x7F) << 24) |
                                                            ((hmac[offset + 1] & 0xFF) << 16) |
                                                            ((hmac[offset + 2] & 0xFF) << 8)  |
                                                            ( hmac[offset + 3] & 0xFF);

                                    const uint32_t code = binary % modulus;

                                    return(std::expected<bool, elegant_exception::elegant_exception>{code == candidate});
                                })
                                .or_else([](const elegant_exception::elegant_exception& cex)
                                {
                                    return std::unexpected(cex);
                                });
                            });
                    });
            }

            [[nodiscard]]
            std::string to_string(uint32_t in_code) const
            {
                inline static constexpr std::string_view totp_to_string_format{"{:0{}}"};

                return std::format(totp_to_string_format,
                                   in_code,
                                   digits
                                  );
            }
    };
} // namespace elegant_otp


