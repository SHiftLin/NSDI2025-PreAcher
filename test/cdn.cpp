#include <PreAcher.hpp>
#include "test_util.h"

#include <csignal>
#include <workflow/HttpUtil.h>
#include <workflow/WFFacilities.h>
#include <workflow/WFHttpServer.h>
#include <workflow/WFTaskFactory.h>

constexpr char CERT_PEM[] = "../../test/share/cert/localhost.crt";
constexpr char KEY_PEM[] = "../../test/share/cert/localhost.key";
const std::string origin_server = "https://localhost:8080";

using namespace protocol;
using std::string;

class RegisterContext : public BaseContext {
public:
  string u{};
  string state{};

  // Only in record stage
  string envU_p{};
  string pubU_p{};

  RegisterContext(HttpRequest *_req, HttpResponse *_resp) : BaseContext(_req, _resp) {}
};

// This map stores <username, {base64(kU), base64(envU_p), pubU}>
// pubU is already converted to ASN.1/DER
std::map<std::string, std::tuple<std::string, std::string, const EVP_PKEY *>> PasswordDatabase{};

std::map<std::string, std::string> AuthChallenge{};

void login_callback(WFHttpTask *task) {
  int state = task->get_state();
  auto *resp = task->get_resp();
  const SeriesWork *series = series_of(task);
  const auto *ctx = static_cast<BaseContext *>(series->get_context());
  auto *proxy_resp = ctx->resp;

  if (state == WFT_STATE_SUCCESS) {
    const void *body;
    size_t len;

    /* Copy the remote webserver's response, to proxy response. */
    resp->get_parsed_body(&body, &len);
    resp->append_output_body_nocopy(body, len);
    *proxy_resp = std::move(*resp);
    proxy_resp->set_header_pair("Connection", "close");
  }
}

void login_server(WFHttpTask *server_task) {
  const auto req = server_task->get_req();
  const auto resp = server_task->get_resp();
  const auto new_url = origin_server + req->get_request_uri();

  char *body = nullptr;
  size_t len = 0;
  req->get_parsed_body((const void **)&body, &len);

  auto *ctx = new BaseContext(req, resp);
  auto req_body = from_json(body);
  if (req_body["s"].empty() || req_body["u"].empty()) {
    return_err(ctx->resp, 400)
  }
  const auto &u = req_body["u"];
  const auto &state = req_body["s"];

  if (state == "h") { // hello
    if (req_body["a_p"].empty()) {
      return_err(ctx->resp, 400)
    }
    const auto &alpha_p = from_base64(req_body["a_p"]);
    // 1. Find stored value
    auto it = PasswordDatabase.find(u);
    if (it == PasswordDatabase.end()) {
      resp->append_output_body("User not found!");
      return_err(ctx->resp, 403)
    }
    const auto &[kU, envU_p, pubU] = it->second;

    const PreAcher_cdn_login_first_network_in network = {
        .alpha_primed = alpha_p,
    };

    const PreAcher_cdn_credential cdn_credential = {
        .k_u = kU,
        .pubU = pubU,
        .envU_p = envU_p,
    };

    // 2. Get beta and generate challenge
    const auto &[success, network_out, temp] = PreAcher_cdn_login_first(network, cdn_credential);

    AuthChallenge[u] = temp.c;

    // 3. Response
    resp->append_output_body(to_json({
        {"vU", network_out.vU},
        {"beta_p", network_out.beta_primed},
        {"envU_p", network_out.envU_p},
        {"c", network_out.c},
    }));
  } else if (state == "r") { // record
    if (req_body["S"].empty() || req_body["M"].empty()) {
      return_err(ctx->resp, 400)
    }
    const auto &S = req_body["S"];
    const auto &M = req_body["M"];

    // 1. Find stored public key
    const auto it = PasswordDatabase.find(u);
    if (it == PasswordDatabase.end()) {
      resp->append_output_body("User not found!");
      return_err(ctx->resp, 403)
    }
    const auto &[kU, envU_p, pubU] = it->second;
    const auto &challenge = AuthChallenge.find(u)->second;

    if (PreAcher_cdn_login_second({.S = S}, {.c = challenge, .pubU_p = pubU})) {
      // Erase challenge
      AuthChallenge.erase(u);

      WFHttpTask *next = WFTaskFactory::create_http_task(new_url, 0, 0, login_callback);
      auto *next_req = next->get_req();
      next_req->append_output_body(to_json({{"u", u}, {"M", M}}));
      next_req->set_method("POST");
      next_req->set_header_pair("Connection", "close");

      SeriesWork *series = series_of(server_task);
      set_context_and_delete(series, ctx, BaseContext *);
      series->push_back(next);
    } else {
      ctx->resp->append_output_body("CDN auth fail!");
      return_err(ctx->resp, 403)
    }
  }
}

void register_callback(WFHttpTask *task) {
  const int state = task->get_state();
  auto *resp = task->get_resp();
  const SeriesWork *series = series_of(task);
  const auto *ctx = static_cast<RegisterContext *>(series->get_context());

  if (state != WFT_STATE_SUCCESS) {
    return_err(ctx->resp, 500)
  }

  const void *body;
  size_t len;
  resp->get_parsed_body(&body, &len);
  if (const auto status_code = resp->get_status_code();
      status_code != std::string("200") || ctx->state == "h") {
    /* Copy the remote webserver's response, to proxy response. */
    resp->append_output_body_nocopy(body, len);
    *ctx->resp = std::move(*resp);
    ctx->resp->set_header_pair("Connection", "close");
  } else {
    auto json = from_json(std::string(static_cast<const char *>(body), len));
    if (json["kU"].empty()) {
      return_err(ctx->resp, 400)
    }
    const auto kU = json["kU"];
    const auto envU_p = ctx->envU_p;
    const auto pubU_txt = ctx->pubU_p;
    const auto aug_pubU = "-----BEGIN PUBLIC KEY-----\n" + pubU_txt + "\n-----END PUBLIC KEY-----";
    BIO *bp = BIO_new_mem_buf(aug_pubU.data(), static_cast<int>(strlen(aug_pubU.data())));
    const EVP_PKEY *pubU = PEM_read_bio_PUBKEY(bp, nullptr, nullptr, nullptr);

    PreAcher_cdn_credential cdn_credential = {
        .k_u = kU,
        .pubU = pubU,
        .envU_p = envU_p,
    };

    PasswordDatabase[ctx->u] = {cdn_credential.k_u, cdn_credential.envU_p, cdn_credential.pubU};

    ctx->resp->set_status_code("200");
  }
}

void register_server(WFHttpTask *server_task) {
  const auto req = server_task->get_req();
  const auto resp = server_task->get_resp();
  const auto new_url = origin_server + req->get_request_uri();

  WFHttpTask *next = WFTaskFactory::create_http_task(new_url, 0, 0, register_callback);

  char *body = nullptr;
  size_t len = 0;
  req->get_parsed_body((const void **)&body, &len);

  auto *ctx = new RegisterContext(req, resp);
  auto req_body = from_json(body);
  if (req_body["s"].empty() || req_body["u"].empty()) {
    return_err(ctx->resp, 400)
  }
  ctx->u = req_body["u"];
  ctx->state = req_body["s"];

  if (ctx->state == "r") { // record
    if (req_body["envU_p"].empty() || req_body["pubU_p"].empty()) {
      return_err(ctx->resp, 400)
    }
    ctx->envU_p = req_body["envU_p"];
    ctx->pubU_p = req_body["pubU_p"];
  }

  req->append_output_body_nocopy(body, len);
  *next->get_req() = std::move(*req);

  SeriesWork *series = series_of(server_task);
  set_context_and_delete(series, ctx, RegisterContext *);
  series->push_back(next);
}

/* This function copies the response from the remote webserver */
void forward_callback(WFHttpTask *task) {
  const int state = task->get_state();
  auto *resp = task->get_resp();
  const SeriesWork *series = series_of(task);
  const auto *ctx = static_cast<BaseContext *>(series->get_context());
  auto *proxy_resp = ctx->resp;

  if (state == WFT_STATE_SUCCESS) {
    const void *body;
    size_t len;
    resp->get_parsed_body(&body, &len);
    resp->append_output_body_nocopy(body, len);
    *proxy_resp = std::move(*resp);
    proxy_resp->set_header_pair("Connection", "close");
  } else {
    return_err(proxy_resp, 500)
  }
}

/* This function forwards the request to the remote webserver. */
void forward_server(WFHttpTask *server_task) {
  const auto req = server_task->get_req();
  auto resp = server_task->get_resp();
  const auto new_url = origin_server + req->get_request_uri();

  WFHttpTask *next = WFTaskFactory::create_http_task(new_url, 0, 0, forward_callback);

  char *body = nullptr;
  size_t len = 0;
  req->get_parsed_body((const void **)&body, &len);
  req->append_output_body_nocopy(body, len);
  *next->get_req() = std::move(*req);

  auto *ctx = new BaseContext(req, resp);
  SeriesWork *series = series_of(server_task);
  set_context_and_delete(series, ctx, BaseContext *);
  series->push_back(next);
}

void process(WFHttpTask *server_task) {
  const auto req = server_task->get_req();
  const auto resp = server_task->get_resp();

  const char *uri = req->get_request_uri();

  fprintf(stdout, "Request-URI: %s\n", uri);
  fflush(stdout);

  if (strcmp(req->get_method(), "POST") == 0) {
    if (strcmp(uri, "/register") == 0) {
      register_server(server_task);
    } else if (strcmp(uri, "/login") == 0) {
      login_server(server_task);
    } else {
      return_err(resp, 404);
    }
  } else {
    forward_server(server_task);
  }
}

static WFFacilities::WaitGroup wait_group(1);

void sig_handler([[maybe_unused]] int signo) { wait_group.done(); }

int main() {
  signal(SIGINT, sig_handler);

  constexpr unsigned short port = 8000;
  auto &&proc = [](auto &&PH1) { process(std::forward<decltype(PH1)>(PH1)); };
  WFHttpServer server(proc);

  int ret = server.start(port, CERT_PEM, KEY_PEM);
  if (ret == 0) {
    wait_group.wait();
    server.stop();
  } else {
    perror("start server");
    exit(1);
  }

  return 0;
}
