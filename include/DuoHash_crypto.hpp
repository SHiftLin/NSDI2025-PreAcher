#ifndef DUOHASH_CRYPTO_HPP
#define DUOHASH_CRYPTO_HPP

#include <PreAcher_crypto.hpp>
#include <minhash.hpp>

#include <string>

std::string LSH(const std::string &username, const std::string &password);

std::string sha256(const std::string &password);

#endif // DUOHASH_CRYPTO_HPP