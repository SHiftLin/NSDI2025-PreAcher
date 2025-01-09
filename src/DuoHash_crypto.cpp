#include <DuoHash_crypto.hpp>

#include <map>
#include <openssl/pem.h>

std::string LSH(const std::string &username, const std::string &password) {
  KmerMinHash minHasher(5, true, username);
  return minHasher.hash(password);
}

// H_1
std::string sha256(const std::string &password) {
  unsigned char result[SHA256_DIGEST_LENGTH]{};
  EVP_Digest(password.c_str(), password.length(), result, nullptr, EVP_sha256(), nullptr);
  return {reinterpret_cast<char *>(result), SHA256_DIGEST_LENGTH};
}
