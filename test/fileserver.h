#ifndef TEST_FILESERVER_H
#define TEST_FILESERVER_H

#include "test_util.h"
#include "workflow/HttpMessage.h"
#include "workflow/WFHttpServer.h"

#include <cstdio>
#include <fcntl.h>
#include <unistd.h>

#define set_user_data_and_free(task, data)                                                         \
  (task)->user_data = (data);                                                                      \
  (task)->set_callback([](WFHttpTask *t) { free(t->user_data); });

class FilePath {
public:
  std::string root, rel_path, abs_path, suffix;

  FilePath() = default;

  FilePath(const FilePath &other) {
    if (this != &other) {
      root = other.root;
      rel_path = other.rel_path;
      abs_path = other.abs_path;
      suffix = other.suffix;
    }
  }

  FilePath &operator=(FilePath &&other) noexcept {
    if (this != &other) {
      root = std::move(other.root);
      rel_path = std::move(other.rel_path);
      abs_path = std::move(other.abs_path);
      suffix = std::move(other.suffix);
    }
    return *this;
  }
};

class FileContext : public BaseContext {
public:
  FilePath fp;

  FileContext(protocol::HttpRequest *_req, protocol::HttpResponse *_resp)
      : BaseContext(_req, _resp) {}
};

const std::map<std::string, std::string> MIME_MAP = {
    {"html", "text/html"}, {"js", "text/javascript"}, {"css", "text/css"}};

std::string get_mime(const std::string &suffix) {
  auto it = MIME_MAP.find(suffix);

  if (it == MIME_MAP.end())
    return "text/plain";
  else
    return it->second;
}

FilePath get_filepath(const char *uri, const char *root) {
  const char *p = uri;
  while (*p && *p != '?')
    p++;
  FilePath fp;
  fp.root = std::string(root);
  fp.rel_path = std::move(std::string(uri, p - uri));
  if (fp.rel_path.back() == '/')
    fp.rel_path += "index.html";
  fp.abs_path = fp.root + fp.rel_path;
  size_t pos = fp.rel_path.find_last_of('.');
  if (pos != std::string::npos)
    fp.suffix = std::move(fp.rel_path.substr(pos + 1));
  return fp;
}

void pread_callback(WFFileIOTask *task) {
  FileIOArgs *args = task->get_args();
  long ret = task->get_retval();
  auto *ctx = (FileContext *)series_of(task)->get_context();

  close(args->fd);
  if (task->get_state() != WFT_STATE_SUCCESS || ret < 0) {
    return_err(ctx->resp, 503)
  } else { /* Use '_nocopy' carefully. */
    ctx->resp->add_header_pair("Content-Type", get_mime(ctx->fp.suffix));
    ctx->resp->append_output_body_nocopy(args->buf, ret);
  }
}

void file_server(WFHttpTask *server_task, FilePath &fp) {
  auto *ctx = new FileContext(server_task->get_req(), server_task->get_resp());
  ctx->fp = std::move(fp);

  int fd = open(ctx->fp.abs_path.c_str(), O_RDONLY);
  if (fd >= 0) {
    size_t size = lseek(fd, 0, SEEK_END);
    void *buf = malloc(size);
    if (buf == nullptr) {
      delete ctx;
      return_err(ctx->resp, 503)
    }
    WFFileIOTask *pread_task = WFTaskFactory::create_pread_task(fd, buf, size, 0, pread_callback);
    /* To implement a more complicated server, please use series' context
     * instead of tasks' user_data to pass/store internal data. */

    set_user_data_and_free(server_task, buf) SeriesWork *series = series_of(server_task);
    set_context_and_delete(series, ctx, FileContext *) series->push_back(pread_task);
  } else {
    return_err(ctx->resp, 404)
  }
}

#endif // TEST_FILESERVER_H