#pragma once

#include <iostream>
#include <map>
#include <nlohmann/json.hpp>
#include <string>
#include <utility>
#include <workflow/HttpMessage.h>

#define return_err(resp, code)                                                                     \
  {                                                                                                \
    set_err(resp, code);                                                                           \
    return;                                                                                        \
  }

#define set_context_and_delete(series, ctx, type)                                                  \
  (series)->set_context(ctx);                                                                      \
  (series)->set_callback([](const SeriesWork *s) { delete (type)s->get_context(); });

class BaseContext {
public:
  protocol::HttpRequest *req;
  protocol::HttpResponse *resp;

  BaseContext(protocol::HttpRequest *_req, protocol::HttpResponse *_resp)
      : req(_req), resp(_resp) {}
};

const std::map<int, std::string> STATUS_MAP = {{400, "Bad Request"},
                                               {403, "Forbidden"},
                                               {404, "Not Found"},
                                               {405, "Method Not Allowed"},
                                               {500, "Internal Server Error"},
                                               {503, "Service Unavailable"}};

inline void set_err(protocol::HttpResponse *resp, int status_code) {
  const auto it = STATUS_MAP.find(status_code);
  std::string status("Unknown Error");
  if (it != STATUS_MAP.end())
    status = it->second;
  std::string code_str = std::to_string(status_code);
  resp->set_status_code(code_str.c_str());
  resp->append_output_body("<html>" + code_str + " " + status + ".</html>");
}

inline std::map<std::string, std::string> from_json(const std::string &json) {
  std::map<std::string, std::string> result;
  try {
    nlohmann::json jsonObj = nlohmann::json::parse(json);
    for (const auto &[key, value] : jsonObj.items()) {
      result[key] = value;
    }
  } catch (nlohmann::json::parse_error &e) {
    std::cerr << "JSON parsing failed: " << e.what() << std::endl;
    return {};
  }
  return result;
}

inline std::string to_json(const std::map<std::string, std::string> &map) {
  nlohmann::json jsonObj;
  for (const auto &[key, value] : map) {
    jsonObj[key] = value;
  }
  return jsonObj.dump();
}
