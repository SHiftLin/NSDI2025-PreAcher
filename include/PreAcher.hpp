#ifndef LIBPREACHER_PREACHER_H
#define LIBPREACHER_PREACHER_H

#include <PreAcher_crypto.hpp>
#include <string>
#include <tuple>

struct PreAcher_server_register_first_network_in {
  const std::string alpha_primed{};

  [[nodiscard]] bool invalid() const { return alpha_primed.empty(); }
};

struct PreAcher_server_register_first_network_out {
  const std::string vU{};
  const std::string beta_primed{};
  const std::string c{};
};

struct PreAcher_server_register_temp {
  const std::string c{};
  const std::string k_u{};

  [[nodiscard]] bool invalid() const { return c.empty() || k_u.empty(); }
};

struct PreAcher_server_register_second_network_in {
  const std::string c{};
  const std::string M{};

  [[nodiscard]] bool invalid() const { return M.empty() || c.empty(); }
};

struct PreAcher_server_register_second_network_out {
  const bool success{};
  const std::string k_u{};
};

struct PreAcher_server_credential {
  const std::string hash{};
  const std::string salt{};

  [[nodiscard]] bool invalid() const { return hash.empty() || salt.empty(); }
};

struct PreAcher_server_login_network_in {
  const std::string u{};
  const std::string M{};

  [[nodiscard]] bool invalid() const { return u.empty() || M.empty(); }
};

std::tuple<bool, PreAcher_server_register_first_network_out, PreAcher_server_register_temp>
PreAcher_server_register_first(const PreAcher_server_register_first_network_in &network);

std::tuple<bool, PreAcher_server_register_second_network_out, PreAcher_server_credential>
PreAcher_server_register_second(const PreAcher_server_register_second_network_in &network,
                                const PreAcher_server_register_temp &temp);

bool PreAcher_server_login(const PreAcher_server_login_network_in &network,
                           const PreAcher_server_credential &credential);

struct PreAcher_cdn_credential {
  const std::string k_u{};
  const EVP_PKEY *pubU{};
  const std::string envU_p{};

  [[nodiscard]] bool invalid() const { return k_u.empty() || pubU == nullptr || envU_p.empty(); }
};

struct PreAcher_cdn_login_first_network_in {
  const std::string alpha_primed{};

  [[nodiscard]] bool invalid() const { return alpha_primed.empty(); }
};

struct PreAcher_cdn_login_first_network_out {
  const std::string vU{};
  const std::string beta_primed{};
  const std::string envU_p{};
  const std::string c{};

  [[nodiscard]] bool invalid() const {
    return vU.empty() || beta_primed.empty() || envU_p.empty() || c.empty();
  }
};

struct PreAcher_cdn_login_temp {
  const std::string c{};
  const EVP_PKEY *pubU_p{};

  [[nodiscard]] bool invalid() const { return c.empty() || pubU_p == nullptr; }
};

struct PreAcher_cdn_login_second_network_in {
  const std::string S{};

  [[nodiscard]] bool invalid() const { return S.empty(); }
};

std::tuple<bool, PreAcher_cdn_login_first_network_out, PreAcher_cdn_login_temp>
PreAcher_cdn_login_first(const PreAcher_cdn_login_first_network_in &network,
                         const PreAcher_cdn_credential &credential);

bool PreAcher_cdn_login_second(const PreAcher_cdn_login_second_network_in &network,
                               const PreAcher_cdn_login_temp &temp);

#endif // LIBPREACHER_PREACHER_H