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

#ifndef __CASS_SSL_HPP_INCLUDED__
#define __CASS_SSL_HPP_INCLUDED__

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <stddef.h>

namespace cass {

class SslSession;
class SslContext {
public:
  virtual SslSession* create_session() = 0;
};

class SslSession {
public:
  virtual bool is_handshake_done() = 0;

  virtual ssize_t read(char* output, size_t size) = 0;
  virtual ssize_t write(const char* output, size_t size) = 0;

  virtual ssize_t encrypt(const char* buf, size_t size) = 0;
  virtual ssize_t decrypt(char* buf, size_t size) = 0;
};

class OpenSslContext : public SslContext {
public:
  OpenSslContext();

  virtual SslSession* create_session();

private:
  SSL_CTX* ssl_ctx_;
};

class OpenSslSession : public SslSession {
public:
  OpenSslSession(SSL_CTX* ssl_ctx);

  ~OpenSslSession();

  virtual bool is_handshake_done();

  virtual ssize_t read(char* buf, size_t size);
  virtual ssize_t write(const char* buf, size_t size);

  virtual ssize_t encrypt(const char* buf, size_t size);
  virtual ssize_t decrypt(char* buf, size_t size);

private:
  SSL* ssl_;
  BIO* incoming_bio_;
  BIO* outgoing_bio_;
};

} // namespace cass

#endif
