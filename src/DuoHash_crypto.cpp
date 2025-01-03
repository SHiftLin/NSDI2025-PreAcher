#include <DuoHash_crypto.hpp>

#include <iostream>
#include <map>
#include <openssl/pem.h>
#include <openssl/rand.h>

static std::string to_hex(uint32_t value) {
  char str[16];
  char *p = &str[16];
  do {
    p--;
    uint32_t digit = value % 16;
    value /= 16;
    *p = (char)(digit >= 10 ? 'a' + (digit - 10) : '0' + digit);
  } while (value > 0);
  return {p, static_cast<size_t>(&str[16] - p)};
}

std::string LSH(const std::string &username, const std::string &password) {
  KmerMinHash minHasher(5, true, username);
  return minHasher.hash(password);
}

// H_1
std::string sha256(const std::string &password) {
  unsigned char result[SHA256_DIGEST_LENGTH] = {0};
  EVP_Digest(password.c_str(), password.length(), result, nullptr, EVP_sha256(), nullptr);
  return {reinterpret_cast<char *>(result), SHA256_DIGEST_LENGTH};
}
