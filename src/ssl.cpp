/*
  Copyright 2014 DataStax

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#include "ssl.hpp"

#include <openssl/err.h>

namespace cass {

int no_verify_callback(int ok, X509_STORE_CTX* store) {
  return 1;
}

OpenSslContext::OpenSslContext()
  : ssl_ctx_(SSL_CTX_new(SSLv3_client_method())) { }

SslSession* OpenSslContext::create_session() {
  return new OpenSslSession(ssl_ctx_);
}

OpenSslSession::OpenSslSession(SSL_CTX* ssl_ctx)
  : ssl_(SSL_new(ssl_ctx))
  , incoming_bio_(BIO_new(BIO_s_mem()))
  , outgoing_bio_(BIO_new(BIO_s_mem())) {
  SSL_set_bio(ssl_, incoming_bio_, outgoing_bio_);
  SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, no_verify_callback);
  //SSL_CTX_set_info_callback(ssl_ctx, info_callback);
  SSL_set_connect_state(ssl_);
}

OpenSslSession::~OpenSslSession() {
  SSL_free(ssl_);
}

bool OpenSslSession::is_handshake_done()  {
  return SSL_is_init_finished(ssl_);
}

ssize_t OpenSslSession::read(char* buf, size_t size)  {
  int rc = 0;
  if (!SSL_is_init_finished(ssl_)) {
    rc = SSL_connect(ssl_);
    if (rc <= 0) {
      int err = SSL_get_error(ssl_, rc);
      if (err != SSL_ERROR_WANT_READ) {
        ERR_print_errors_fp(stderr);
        return -1;
      }
    }
  }

  size_t count = 0;
  while ((rc = BIO_read(outgoing_bio_, buf + count, size - count)) > 0) {
    count += rc;
  }
  return count;
}

ssize_t OpenSslSession::write(const char* buf, size_t size)  {
  int rc = BIO_write(incoming_bio_, buf, size);
  if (rc <= 0) {
    return -1;
  }
  return rc;
}

ssize_t OpenSslSession::encrypt(const char* buf, size_t size) {
  int rc = SSL_write(ssl_, buf, size);
  if (rc < 0) {
    return -1;
  }
  return rc;
}

ssize_t OpenSslSession::decrypt(char* buf, size_t size)  {
  int rc = SSL_read(ssl_, buf, size);
  if (rc < 0) {
    return -1;
  }
  return rc;
}

} // namespace cass
