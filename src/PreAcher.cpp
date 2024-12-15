#include <PreAcher.hpp>

std::tuple<bool, PreAcher_server_register_first_network_out, PreAcher_server_register_temp>
PreAcher_server_register_first(const PreAcher_server_register_first_network_in &network) {
  if (network.invalid()) {
    return {false, {}, {}};
  }

  const auto a_p = from_base64(network.alpha_primed);
  const auto [beta_primed, vU, kU] = getBeta(a_p);

  auto challenge = to_base64(get_challenge());

  const PreAcher_server_register_first_network_out network_out{
      .vU = to_base64(vU),
      .beta_primed = to_base64(beta_primed),
      .c = challenge,
  };
  const PreAcher_server_register_temp temp_out{
      .c = challenge,
      .k_u = to_base64(kU),
  };

  return {true, network_out, temp_out};
}

std::tuple<bool, PreAcher_server_register_second_network_out, PreAcher_server_credential>
PreAcher_server_register_second(const PreAcher_server_register_second_network_in &network,
                                const PreAcher_server_register_temp &temp) {
  if (network.invalid() || temp.invalid()) {
    return {false, {}, {}};
  }

  if (temp.c != network.c) {
    return {false, {}, {}};
  }

  const auto &Nonced_password = decrypt_base64(network.M);
  std::size_t space = Nonced_password.find(' ');
  if (space == std::string::npos) {
    return {false, {}, {}};
  }

  const auto &password = Nonced_password.substr(space + 1);
  const auto &salt = generate_salt(32);
  const auto &hash = pbkdf2(password.c_str(), password.length(), salt.c_str(), salt.length());

  const PreAcher_server_credential password_out{
      .hash = hash,
      .salt = salt,
  };
  const PreAcher_server_register_second_network_out network_out{
      .success = true,
      .k_u = temp.k_u, // k_u is base64 encoded
  };

  return {true, network_out, password_out};
}

bool PreAcher_server_login(const PreAcher_server_login_network_in &network,
                           const PreAcher_server_credential &credential) {
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

std::tuple<bool, PreAcher_cdn_login_first_network_out, PreAcher_cdn_login_temp>
PreAcher_cdn_login_first(const PreAcher_cdn_login_first_network_in &network,
                         const PreAcher_cdn_credential &credential) {
  if (network.invalid() || credential.invalid()) {
    return {false, {}, {}};
  }

  const auto &[beta_p, vU] = getBetaPrimed(from_base64(credential.k_u), network.alpha_primed);
  const auto &challenge = get_challenge();

  const PreAcher_cdn_login_temp temp{
      .c = challenge,
      .pubU_p = credential.pubU,
  };

  const PreAcher_cdn_login_first_network_out network_out{
      .vU = to_base64(vU),
      .beta_primed = to_base64(beta_p),
      .envU_p = credential.envU_p,
      .c = to_base64(challenge),
  };

  return {true, network_out, temp};
}

bool PreAcher_cdn_login_second(const PreAcher_cdn_login_second_network_in &network,
                               const PreAcher_cdn_login_temp &temp) {
  if (network.invalid() || temp.invalid()) {
    return false;
  }

  return verifyIEEEP1363(temp.pubU_p, temp.c, from_base64(network.S));
}
