#include "fileserver.h"
#include "test_util.h"
#include <PreAcher.hpp>

#include <csignal>
#include <nlohmann/json.hpp>
#include <sodium.h>
#include <workflow/WFFacilities.h>
#include <workflow/WFTaskFactory.h>

constexpr char CERT_PEM[] = "../../test/share/cert/localhost.crt";
constexpr char KEY_PEM[] = "../../test/share/cert/localhost.key";
constexpr char ROOT_DIR[] = "../../test/share/static";
constexpr char CRYPTO_PEM[] = "../../test/single_server.pem";

std::map<std::string, PreAcher_server_register_temp> RegistParams;

std::map<std::string, std::tuple<std::string, std::string>> PasswordDB{};

void auth_server(WFHttpTask *server_task) {
  const auto *ctx = new BaseContext(server_task->get_req(), server_task->get_resp());

  char *body = nullptr;
  size_t len = 0;
  ctx->req->get_parsed_body((const void **)&body, &len);
  auto req_body = from_json(body);
  if (req_body["u"].empty() || req_body["M"].empty()) {
    return_err(ctx->resp, 400)
  }
  const auto u = req_body["u"];
  const auto M = req_body["M"];

  // Search for the user in PasswordDB
  const auto it = PasswordDB.find(u);
  if (it == PasswordDB.end()) {
    return_err(ctx->resp, 403) // User not exist
  }
  const auto &[hash, salt] = it->second;

  if (PreAcher_server_login({.u = u, .M = M}, {.hash = hash, .salt = salt})) {
    ctx->resp->set_status_code("200");
    return;
  }
  return_err(ctx->resp, 403);
}

void regst_server(WFHttpTask *server_task) {
  const auto *ctx = new BaseContext(server_task->get_req(), server_task->get_resp());

  char *body = nullptr;
  size_t len = 0;
  ctx->req->get_parsed_body((const void **)&body, &len);
  auto req_body = from_json(body);
  if (req_body["s"].empty() || req_body["u"].empty()) {
    return_err(ctx->resp, 400)
  }
  const auto &state = req_body["s"];
  const auto &u = req_body["u"];

  if (state == "h") {
    // Search for the user in PasswordDB
    if (const auto it = PasswordDB.find(u); it != PasswordDB.end()) {
      // return_err(ctx->resp, 403);
      std::cerr << "Overwriting" << std::endl;
    }

    const auto &[success, network_out, temp_out] =
        PreAcher_server_register_first({.alpha_primed = req_body["a_p"]});

    if (!success) {
      return_err(ctx->resp, 400)
    }

    RegistParams.insert({u, temp_out});
    ctx->resp->append_output_body(to_json({
        {"vU", network_out.vU},
        {"b_p", network_out.beta_primed},
        {"c", network_out.c},
    }));
    ctx->resp->set_status_code("200");
  } else if (state == "r") {
    const auto value = RegistParams.find(u);
    if (value == RegistParams.end()) {
      return_err(ctx->resp, 403)
    }

    const auto &envU_p = req_body["envU_p"];
    const auto &pubU_p = req_body["pubU_p"];
    const auto &c = req_body["c"];
    const auto &M = req_body["M"];
    if (req_body["envU_p"].empty() || req_body["pubU_p"].empty()) {
      return_err(ctx->resp, 400)
    }

    const auto &k_u = value->second.k_u;
    const auto &c_solution = value->second.c;

    const auto &[success, network_out, credential] =
        PreAcher_server_register_second({.c = c, .M = M}, {.c = c_solution, .k_u = k_u});

    if (!success) {
      return_err(ctx->resp, 400)
    }

    // Success
    RegistParams.erase(u);
    PasswordDB[u] = {credential.hash, credential.salt};

    ctx->resp->append_output_body(
        to_json({{"u", u}, {"kU", network_out.k_u}, {"pubU_p", pubU_p}, {"envU_p", envU_p}}));
    ctx->resp->set_status_code("200");
  }
}

void process(WFHttpTask *server_task, const char *root) {
  protocol::HttpRequest *req = server_task->get_req();

  const char *uri = req->get_request_uri();

  fprintf(stdout, "Request-URI: %s\n", uri);
  fflush(stdout);

  if (strcmp(req->get_method(), "GET") == 0) {
    FilePath fp = get_filepath(uri, root);
    file_server(server_task, fp);
  } else {
    if (strcmp(uri, "/register") == 0)
      regst_server(server_task);
    else if (strcmp(uri, "/login") == 0)
      auth_server(server_task);
  }
}

static WFFacilities::WaitGroup wait_group(1);

void sig_handler([[maybe_unused]] int signo) { wait_group.done(); }

int main() {
  signal(SIGINT, sig_handler);

  crypto_init(CRYPTO_PEM);

  constexpr unsigned short port = 8080;
  auto &&proc = [](auto &&PH1) { process(std::forward<decltype(PH1)>(PH1), ROOT_DIR); };
  WFHttpServer server(proc);

  int ret = server.start(port, CERT_PEM, KEY_PEM);
  if (ret == 0) {
    wait_group.wait();
    server.stop();
  } else {
    perror("start server");
    exit(1);
  }
  crypto_cleanup();

  return 0;
}
