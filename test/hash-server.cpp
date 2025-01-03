#include "fileserver.h"
#include "test_util.h"
#include <DuoHash.hpp>

#include <csignal>
#include <sodium.h>
#include <workflow/WFFacilities.h>
#include <workflow/WFTaskFactory.h>

constexpr char CERT_PEM[] = "../../test/share/cert/localhost.crt";
constexpr char KEY_PEM[] = "../../test/share/cert/localhost.key";
constexpr char ROOT_DIR[] = "../../test/share/static";
constexpr char CRYPTO_PEM[] = "../../test/server.pem";

using std::map;
using std::pair;
using std::string;
using std::vector;

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

  if (DuoHash_server_login({.M = M}, {.hash = hash, .salt = salt})) {
    ctx->resp->set_status_code("200");
    return;
  }
  return_err(ctx->resp, 403);
}

void regst_server(WFHttpTask *server_task) {
  auto *ctx = new BaseContext(server_task->get_req(), server_task->get_resp());

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
  if (const auto search = PasswordDB.find(u); search != PasswordDB.end()) {
    // return_err(ctx->resp, 403);
    std::cerr << "Overwriting" << std::endl;
  }

  const auto &[success, network_out, credential] = DuoHash_server_register({.u = u, .M = M});

  if (!success) {
    return_err(ctx->resp, 400)
  }

  PasswordDB[u] = {credential.hash, credential.salt};

  ctx->resp->set_status_code("200");
  ctx->resp->append_output_body(to_json({{"h", network_out.h}, {"s", network_out.s}}));
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

  int ret = server.start(port, CERT_PEM, KEY_PEM); /* https server */
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
