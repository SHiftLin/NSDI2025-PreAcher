#include "test_util.h"

#include <DuoHash.hpp>
#include <PreAcher.hpp>

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

  RegisterContext(HttpRequest *_req, HttpResponse *_resp) : BaseContext(_req, _resp) {}
};

// This map stores <username, {base64(h_u), s}>
std::map<std::string, std::tuple<std::string, std::string>> PasswordDatabase{};

void login_callback(WFHttpTask *task) {
  int state = task->get_state();
  auto *resp = task->get_resp();
  SeriesWork *series = series_of(task);
  auto *ctx = (BaseContext *)series->get_context();

  if (state == WFT_STATE_SUCCESS) {
    if (resp->get_status_code() == std::string("200")) {
      ctx->resp->set_status_code("200");
      ctx->resp->append_output_body("Login successful");
    } else {
      ctx->resp->set_status_code(resp->get_status_code());
      ctx->resp->append_output_body("Wrong password");
    }
  } else {
    ctx->resp->set_status_code("500");
    ctx->resp->append_output_body("500 Internal Server Error");
  }
}

void login_server(WFHttpTask *server_task) {
  auto req = server_task->get_req();
  auto resp = server_task->get_resp();
  auto *ctx = new BaseContext(req, resp);

  char *body = nullptr;
  size_t len = 0;
  ctx->req->get_parsed_body((const void **)&body, &len);
  auto req_body = from_json(body);
  if (req_body["u"].empty() || req_body["h"].empty() || req_body["M"].empty()) {
    return_err(ctx->resp, 400)
  }
  const auto u = req_body["u"];
  const auto h = req_body["h"];
  const auto M = req_body["M"];

  auto it = PasswordDatabase.find(u);
  if (it == PasswordDatabase.end()) {
    return_err(ctx->resp, 403) // User does not exist
  }
  const auto &[h_u, salt] = it->second;

  if (!DuoHash_cdn_login({h}, {h_u, salt})) {
    return_err(ctx->resp, 403) // Incorrect password
  }

  auto new_url = origin_server + req->get_request_uri();
  WFHttpTask *next = WFTaskFactory::create_http_task(new_url, 0, 0, login_callback);
  auto *next_req = next->get_req();
  next_req->append_output_body(to_json({{"u", u}, {"M", M}}));
  next_req->set_method("POST");
  next_req->set_header_pair("Connection", "close");

  SeriesWork *series = series_of(server_task);
  set_context_and_delete(series, ctx, BaseContext *);
  series->push_back(next);
}

void register_callback(WFHttpTask *task) {
  int state = task->get_state();
  auto *resp = task->get_resp();
  SeriesWork *series = series_of(task);
  auto *ctx = (RegisterContext *)series->get_context();

  if (state == WFT_STATE_SUCCESS) {
    const void *body;
    size_t len;
    resp->get_parsed_body(&body, &len);
    auto json = from_json(std::string((const char *)body, len));
    if (json["h"].empty() || json["s"].empty()) {
      ctx->resp->set_status_code("400");
      ctx->resp->append_output_body("Bad Request");
    }
    const auto h = json.at("h");
    const auto s = json.at("s");
    PasswordDatabase[ctx->u] = {h, s};
    ctx->resp->set_status_code("200");
  } else {
    ctx->resp->set_status_code("500");
    ctx->resp->append_output_body("500 Internal Server Error");
  }
}

void register_server(WFHttpTask *server_task) {
  auto req = server_task->get_req();
  auto resp = server_task->get_resp();
  auto new_url = origin_server + req->get_request_uri();

  WFHttpTask *next = WFTaskFactory::create_http_task(new_url, 0, 0, register_callback);

  char *body = nullptr;
  size_t len = 0;
  req->get_parsed_body((const void **)&body, &len);

  auto *ctx = new RegisterContext(req, resp);
  auto json = from_json(body);
  if (json["u"].empty()) {
    return_err(resp, 400)
  }
  ctx->u = json["u"];

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
