#ifndef PREACHER_CRYPTO_HPP
#define PREACHER_CRYPTO_HPP

#include <cppcodec/base64_rfc4648.hpp>
#include <openssl/rand.h>
#include <string>
#include <tuple>

constexpr size_t CHALLENGE_BYTES = 32;
constexpr size_t SIGN_BYTES = 64;

inline std::string from_base64(const std::string &encoded) {
  return cppcodec::base64_rfc4648::decode<std::string>(encoded);
}

inline std::string to_base64(const std::string &plaintext) {
  return cppcodec::base64_rfc4648::encode<std::string>(plaintext);
}

inline std::string get_challenge() {
  std::string challenge(CHALLENGE_BYTES, 0);
  RAND_bytes(reinterpret_cast<unsigned char *>(&challenge[0]), CHALLENGE_BYTES);
  return challenge;
}

inline std::string generate_salt(size_t size) {
  unsigned char salt[size];
  RAND_bytes(salt, static_cast<int>(size));
  std::string result(reinterpret_cast<char *>(salt), size);
  return result;
}

std::tuple<std::string, std::string, std::string> generate_X25519_key();

std::tuple<std::string, std::string, std::string> getBeta(const std::string &alpha_primed);

std::string pbkdf2(const char *password, size_t pass_len, const char *salt, size_t salt_len);

bool pbkdf2_verify(const std::string &password, const std::string &salt, const std::string &hash);

inline EVP_PKEY *server_key_rsa;

std::string decrypt_base64(const std::string &ciphertext);

void crypto_init(const std::string &server_cert_pem);

void crypto_cleanup();

int verifyIEEEP1363(const EVP_PKEY *pubU, const std::string &challenge, const std::string &sign);

std::tuple<std::string, std::string> getBetaPrimed(const std::string &kU,
                                                   const std::string &alpha_primed);

#endif // PREACHER_CRYPTO_HPP