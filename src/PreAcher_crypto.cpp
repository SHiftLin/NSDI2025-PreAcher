#include <PreAcher_crypto.hpp>
#include <cstddef>
#include <iostream>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <sodium.h>
#include <string>

std::tuple<std::string, std::string, std::string> generate_X25519_key() {
  unsigned char ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
  unsigned char ed25519_skpk[crypto_sign_ed25519_SECRETKEYBYTES];
  unsigned char pk[crypto_scalarmult_curve25519_BYTES];
  unsigned char sk[crypto_scalarmult_curve25519_BYTES];

  crypto_sign_ed25519_keypair(ed25519_pk, ed25519_skpk);

  if (crypto_sign_ed25519_pk_to_curve25519(pk, ed25519_pk) < 0)
    std::cerr << "Error converting public key" << std::endl;
  if (crypto_sign_ed25519_sk_to_curve25519(sk, ed25519_skpk) < 0)
    std::cerr << "Error converting secret key" << std::endl;

  std::string public_key(reinterpret_cast<char *>(pk), crypto_box_PUBLICKEYBYTES);
  std::string secret_key(reinterpret_cast<char *>(sk), crypto_box_SECRETKEYBYTES);
  std::string ed25519_key(reinterpret_cast<char *>(ed25519_pk), crypto_sign_ed25519_PUBLICKEYBYTES);

  return {to_base64(public_key), to_base64(secret_key), to_base64(ed25519_key)};
}

std::tuple<std::string, std::string, std::string> getBeta(const std::string &alpha_primed) {
  u_char alpha_primed_c[crypto_core_ristretto255_BYTES];
  memcpy(alpha_primed_c, alpha_primed.c_str(), crypto_core_ristretto255_BYTES);
  assert(alpha_primed.length() == crypto_core_ristretto255_BYTES);

  u_char beta_primed[crypto_core_ristretto255_BYTES];
  u_char kU[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_random(kU);

  if (crypto_scalarmult_ristretto255(beta_primed, kU, alpha_primed_c) < 0)
    std::cerr << "Error in scalar multiplication" << std::endl;
  u_char vU[crypto_core_ristretto255_BYTES];
  crypto_scalarmult_ristretto255_base(vU, kU);

  std::string beta_primed_str(reinterpret_cast<char *>(beta_primed),
                              crypto_core_ristretto255_BYTES);
  std::string vU_str(reinterpret_cast<char *>(vU), crypto_core_ristretto255_BYTES);
  std::string kU_str(reinterpret_cast<char *>(kU), crypto_core_ristretto255_SCALARBYTES);
  return {beta_primed_str, vU_str, kU_str};
}

std::string pbkdf2(const char *password, size_t pass_len, const char *salt, size_t salt_len) {
  constexpr size_t hash_len = 256;
  unsigned char output[hash_len];
  constexpr size_t iterations = 10000;

  PKCS5_PBKDF2_HMAC(password, static_cast<int>(pass_len),
                    reinterpret_cast<const unsigned char *>(salt), static_cast<int>(salt_len),
                    iterations, EVP_sha256(), hash_len, output);

  std::string result(reinterpret_cast<char *>(output), hash_len);
  return result;
}

bool pbkdf2_verify(const std::string &password, const std::string &salt, const std::string &hash) {
  return pbkdf2(password.c_str(), password.length(), salt.c_str(), salt.length()) == hash;
}

std::string decrypt_base64(const std::string &ciphertext) {
  const auto decoded_str = from_base64(ciphertext);
  const auto *ciphertext_cstr = reinterpret_cast<const unsigned char *>(decoded_str.c_str());
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(server_key_rsa, nullptr);
  EVP_PKEY_decrypt_init(ctx);
  EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
  const EVP_MD *sha256 = EVP_sha256();
  EVP_PKEY_CTX_set_rsa_oaep_md(ctx, sha256);
  EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, nullptr, 0);

  const size_t ciphertext_len = decoded_str.size();
  // First call to get the size of the plaintext
  size_t plaintext_len;
  EVP_PKEY_decrypt(ctx, nullptr, &plaintext_len, ciphertext_cstr, ciphertext_len);
  auto *plaintext = static_cast<unsigned char *>(malloc(plaintext_len));
  EVP_PKEY_decrypt(ctx, plaintext, &plaintext_len, ciphertext_cstr, ciphertext_len);
  std::string plaintext_str(reinterpret_cast<char *>(plaintext), plaintext_len);
  free(plaintext);
  EVP_PKEY_CTX_free(ctx);
  return plaintext_str;
}

static EVP_PKEY *read_from_file(const std::string &path) {
  FILE *fp = fopen(path.c_str(), "r");
  EVP_PKEY *pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
  fclose(fp);
  if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
    std::cerr << "The provided key is not an RSA key" << std::endl;
    EVP_PKEY_free(pkey);
    return nullptr;
  }
  return pkey;
}

void crypto_init(const std::string &server_cert_pem) {
  OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, nullptr);
  OpenSSL_add_all_algorithms();
  server_key_rsa = read_from_file(server_cert_pem);
}

void crypto_cleanup() { EVP_PKEY_free(server_key_rsa); }

static int verify(const char *msg, const EVP_PKEY *pub_key, const unsigned char *sig,
                  const size_t slen, const size_t msg_len) {
  EVP_MD_CTX *mdctx;

  if (!((mdctx = EVP_MD_CTX_create())))
    goto err;

  if (1 !=
      EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr, const_cast<EVP_PKEY *>(pub_key)))
    goto err;

  if (1 != EVP_DigestVerifyUpdate(mdctx, msg, msg_len))
    goto err;

  if (1 != EVP_DigestVerifyFinal(mdctx, sig, slen))
    goto err;

  return 1;
err:
  return 0;
}

int verifyIEEEP1363(const EVP_PKEY *pubU, const std::string &challenge, const std::string &sign) {
  // Convert to ASN.1/DER
  ECDSA_SIG *sig = ECDSA_SIG_new();
  BIGNUM *r = BN_new(), *s = BN_new();
  BN_bin2bn(reinterpret_cast<const u_char *>(sign.c_str()), SIGN_BYTES / 2, r);
  BN_bin2bn(reinterpret_cast<const u_char *>(sign.c_str()) + SIGN_BYTES / 2, SIGN_BYTES / 2, s);
  ECDSA_SIG_set0(sig, r, s);
  auto *new_der = static_cast<unsigned char *>(malloc(256 * sizeof(unsigned char))),
       *der_pp = new_der;
  const int new_len = i2d_ECDSA_SIG(sig, &der_pp);

  const int result = verify(&challenge[0], pubU, new_der, new_len, CHALLENGE_BYTES);
  free(new_der);
  return result;
}

std::tuple<std::string, std::string> getBetaPrimed(const std::string &kU,
                                                   const std::string &alpha_primed) {
  u_char alpha_primed_c[crypto_core_ristretto255_BYTES];
  memcpy(alpha_primed_c, alpha_primed.c_str(), crypto_core_ristretto255_BYTES);
  assert(alpha_primed.length() == crypto_core_ristretto255_BYTES);

  u_char kU_c[crypto_core_ristretto255_SCALARBYTES];
  memcpy(kU_c, kU.c_str(), crypto_core_ristretto255_SCALARBYTES);
  assert(kU.length() == crypto_core_ristretto255_SCALARBYTES);

  u_char beta_primed[crypto_core_ristretto255_BYTES];

  if (crypto_scalarmult_ristretto255(beta_primed, kU_c, alpha_primed_c) < 0)
    std::cerr << "Error in scalar multiplication" << std::endl;
  u_char vU[crypto_core_ristretto255_BYTES];
  crypto_scalarmult_ristretto255_base(vU, kU_c);

  std::string beta_primed_str(reinterpret_cast<char *>(beta_primed),
                              crypto_core_ristretto255_BYTES);
  std::string vU_str(reinterpret_cast<char *>(vU), crypto_core_ristretto255_BYTES);
  return {beta_primed_str, vU_str};
}
