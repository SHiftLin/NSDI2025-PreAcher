#ifndef MINHASH
#define MINHASH

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <random>
#include <set>
#include <string>
#include <utility>

#include <openssl/hmac.h>
#include <openssl/sha.h>

class KmerMinHash {
  static constexpr int BLOCK_SIZE = SHA256_DIGEST_LENGTH;

  int k;
  bool weighted;
  unsigned char key[BLOCK_SIZE]{};

  std::string zero;
  std::set<std::string> hs_zero;

public:
  KmerMinHash(const int k, const bool weighted, const std::string &username,
              const int max_zero_cnt = 20)
      : k(k), weighted(weighted) {
    kgen(username);

    zero = std::string(k, 0);
    for (int i = 0; i < max_zero_cnt; i++) {
      std::string h_zero = prp_enc(zero, i);
      hs_zero.insert(h_zero);
    }
  }

  void kgen(const std::string &username) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len = 0;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
      throw std::runtime_error("Failed to create EVP_MD_CTX.");
    }

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr)) {
      EVP_MD_CTX_free(mdctx);
      throw std::runtime_error("EVP_DigestInit_ex failed.");
    }

    if (1 != EVP_DigestUpdate(mdctx, username.c_str(), username.size())) {
      EVP_MD_CTX_free(mdctx);
      throw std::runtime_error("EVP_DigestUpdate failed.");
    }

    if (1 != EVP_DigestFinal_ex(mdctx, hash, &len)) {
      EVP_MD_CTX_free(mdctx);
      throw std::runtime_error("EVP_DigestFinal_ex failed.");
    }

    EVP_MD_CTX_free(mdctx);

    memcpy(key, hash, BLOCK_SIZE);
  }

  [[nodiscard]] std::string prp_enc(const std::string &s, const uint16_t idx) const {
    unsigned char data[2 + s.size()];
    *reinterpret_cast<uint16_t *>(data) = htons(idx);
    memcpy(data + 2, s.c_str(), s.size());

    unsigned char hash[BLOCK_SIZE];
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, BLOCK_SIZE, EVP_sha256(), nullptr);
    HMAC_Update(ctx, data, sizeof(data));
    unsigned int len;
    HMAC_Final(ctx, hash, &len);
    HMAC_CTX_free(ctx);

    return {reinterpret_cast<char *>(hash), len};
  }

  std::string min_without_zero(const std::set<std::string> &hs) {
    // Default lexicographical order
    for (auto h : hs) {
      if (hs_zero.find(h) == hs_zero.end())
        return h;
    }
    return *hs_zero.begin();
  }

  std::string hash(const std::string &str) {
    std::string lower(std::max(16ul, str.size()), 0);
    for (int i = 0; i < str.size(); i++)
      lower[i] = tolower(str[i]);
    const size_t n = lower.size();

    std::set<std::string> hs;
    std::map<std::string, int> kmer_cnt;
    for (size_t i = 0; i <= n - k; i++) {
      std::string kmer = lower.substr(i, k);
      int cnt = 0;
      if (weighted) {
        if (auto it = kmer_cnt.find(kmer); it != kmer_cnt.end())
          cnt = it->second;
        cnt++;
        kmer_cnt[kmer] = cnt;
      }
      std::string h = prp_enc(kmer, cnt);
      hs.insert(h);
    }
    const auto h = min_without_zero(hs);
    return to_hex(h);
  }

private:
  static std::string to_hex(const std::string &s) {
    std::stringstream stream;
    for (const unsigned char c : s)
      stream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    return stream.str();
  }
};

#endif