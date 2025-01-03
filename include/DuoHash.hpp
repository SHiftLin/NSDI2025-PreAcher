#ifndef LIBPREACHER_DUOHASH_H
#define LIBPREACHER_DUOHASH_H

#include <DuoHash_crypto.hpp>
#include <string>
#include <tuple>

struct DuoHash_server_register_network_in {
  const std::string u{};
  const std::string M{};

  [[nodiscard]] bool invalid() const { return u.empty() || M.empty(); }
};

struct DuoHash_server_register_network_out {
  const std::string h{};
  const std::string s{};

  [[nodiscard]] bool invalid() const { return h.empty() || s.empty(); }
};

struct DuoHash_credential {
  const std::string hash{};
  const std::string salt{};

  [[nodiscard]] bool invalid() const { return hash.empty() || salt.empty(); }
};

struct DuoHash_server_login_network_in {
  const std::string M{};

  [[nodiscard]] bool invalid() const { return M.empty(); }
};

std::tuple<bool, DuoHash_server_register_network_out, DuoHash_credential>
DuoHash_server_register(const DuoHash_server_register_network_in &network);

bool DuoHash_server_login(const DuoHash_server_login_network_in &network,
                          const DuoHash_credential &credential);

struct DuoHash_cdn_network_in {
  const std::string h{};

  [[nodiscard]] bool invalid() const { return h.empty(); }
};

bool DuoHash_cdn_login(const DuoHash_cdn_network_in &network, const DuoHash_credential &credential);

#endif // LIBPREACHER_DUOHASH_H
