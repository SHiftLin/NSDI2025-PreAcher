#include <DuoHash.hpp>

std::tuple<bool, DuoHash_server_register_network_out, DuoHash_credential>
DuoHash_server_register(const DuoHash_server_register_network_in &network) {
  if (network.invalid()) {
    return {false, {}, {}};
  }

  const auto &Nonced_password = decrypt_base64(network.M);
  const size_t space = Nonced_password.find(' ');
  if (space == std::string::npos) {
    return {false, {}, {}};
  }
  // Write to PasswordDB
  const auto &password = Nonced_password.substr(space + 1);
  const auto &LSH_p = LSH(network.u, password);
  const auto &H_1_LSH_p = to_base64(sha256(LSH_p)); // H_1
  const auto &LSH_salt = to_base64(generate_salt(32));
  const auto &h_u = pbkdf2(H_1_LSH_p.c_str(), H_1_LSH_p.length(), LSH_salt.c_str(),
                           LSH_salt.length()); // H_2

  const auto &salt = generate_salt(32);
  const auto &hash = pbkdf2(password.c_str(), password.length(), salt.c_str(), salt.length());

  const DuoHash_server_register_network_out out{
      .h = to_base64(h_u),
      .s = LSH_salt,
  };

  const DuoHash_credential cred{
      .hash = hash,
      .salt = salt,
  };

  return {true, out, cred};
}

bool DuoHash_server_login(const DuoHash_server_login_network_in &network,
                          const DuoHash_credential &credential) {
  if (network.invalid() || credential.invalid()) {
    return false;
  }

  const auto &Nonced_password = decrypt_base64(network.M);
  const std::size_t space = Nonced_password.find(' ');
  if (space == std::string::npos) {
    return false;
  }

  const auto &password = Nonced_password.substr(space + 1);
  const auto &[hash, salt] = credential;
  return pbkdf2_verify(password, salt, hash);
}

bool DuoHash_cdn_login(const DuoHash_cdn_network_in &network,
                       const DuoHash_credential &credential) {
  if (network.invalid() || credential.invalid()) {
    return false;
  }

  const auto h = network.h;
  const auto &[h_u, salt] = credential;
  const auto &user_h_u = pbkdf2(h.c_str(), h.size(), salt.c_str(), salt.size()); // H_2

  return to_base64(user_h_u) == h_u;
}