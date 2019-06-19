#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include <sys/time.h>

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <vector>

static bool chkerr(int err)
{
  if (err == SSL_ERROR_SYSCALL)
  {
    ERR_print_errors_fp(stdout);
    puts("error");
    exit(1);
    return true;
  }
  return err == 0;
}

class Context
{
  ssl_ctx_st *m_ctx;

public:
  Context(ssl_ctx_st *ctx)
    : m_ctx(ctx)
  {
    SSL_CTX_set_options(m_ctx,
                        SSL_OP_NO_COMPRESSION |
                        SSL_OP_NO_RENEGOTIATION);
  }

  ~Context()
  {
    SSL_CTX_free(m_ctx);
  }

  ssl_st * open()
  {
    return SSL_new(m_ctx);
  }

  void load_server_creds()
  {
    int err;
    err = SSL_CTX_use_certificate_chain_file(m_ctx, "../rustls/test-ca/rsa/end.fullchain");
    assert(err == 1);
    err = SSL_CTX_use_PrivateKey_file(m_ctx, "../rustls/test-ca/rsa/end.key", SSL_FILETYPE_PEM);
    assert(err == 1);
  }

  void load_client_creds()
  {
    int err;
    err = SSL_CTX_load_verify_locations(m_ctx, "../rustls/test-ca/rsa/ca.cert", NULL);
    assert(err == 1);
  }

  void set_version(int minversion, int maxversion)
  {
    SSL_CTX_set_min_proto_version(m_ctx, minversion);
    SSL_CTX_set_max_proto_version(m_ctx, maxversion);
  }

  void set_ciphers(const char *ciphers)
  {
    if (!strcmp(ciphers, "TLS_AES_128_GCM_SHA256") ||
        !strcmp(ciphers, "TLS_AES_256_GCM_SHA384") ||
        !strcmp(ciphers, "TLS_CHACHA20_POLY1305_SHA256"))
    {
      set_version(TLS1_3_VERSION, TLS1_3_VERSION);
      SSL_CTX_set_ciphersuites(m_ctx, ciphers);
    } else {
      set_version(TLS1_2_VERSION, TLS1_2_VERSION);
      SSL_CTX_set_cipher_list(m_ctx, ciphers);
    }
  }

  void enable_resume()
  {
    SSL_CTX_set_session_cache_mode(m_ctx, SSL_SESS_CACHE_BOTH);
    SSL_CTX_set_session_id_context(m_ctx, (const uint8_t *) "localhost", strlen("localhost"));
  }

  void bodge_disable_resume()
  {
    // To allow ticket reuse, pretend we're not caching client sessions
    SSL_CTX_set_session_cache_mode(m_ctx, SSL_SESS_CACHE_SERVER);
  }

  void disable_tickets()
  {
    long opts = SSL_CTX_get_options(m_ctx);
    SSL_CTX_set_options(m_ctx, opts | SSL_OP_NO_TICKET);
  }

  void dump_sess_stats()
  {
    printf("connects: %ld, connects-good: %ld, accepts: %ld, accepts-good: %ld\n",
           SSL_CTX_sess_connect(m_ctx),
           SSL_CTX_sess_connect_good(m_ctx),
           SSL_CTX_sess_accept(m_ctx),
           SSL_CTX_sess_accept_good(m_ctx));
    printf("sessions: %ld, hits: %ld, misses: %ld\n",
           SSL_CTX_sess_number(m_ctx),
           SSL_CTX_sess_hits(m_ctx),
           SSL_CTX_sess_misses(m_ctx));
  }

  static Context server()
  {
    return Context(SSL_CTX_new(TLS_server_method()));
  }

  static Context client()
  {
    return Context(SSL_CTX_new(TLS_client_method()));
  }
};

class Conn
{
  ssl_st *m_ssl;
  bio_st *m_reads_from;
  bio_st *m_writes_to;

  Conn(const Conn&) = delete;
  Conn & operator=(const Conn&) = delete;

public:
  Conn(ssl_st *ssl)
    : m_ssl(ssl),
      m_reads_from(BIO_new(BIO_s_mem())),
      m_writes_to(BIO_new(BIO_s_mem()))
  {
    SSL_set0_rbio(m_ssl, m_reads_from);
    SSL_set0_wbio(m_ssl, m_writes_to);
  }

  Conn(Conn&& other)
    : m_ssl(other.m_ssl),
      m_reads_from(other.m_reads_from),
      m_writes_to(other.m_writes_to)
  {
    other.m_ssl = nullptr;
    other.m_reads_from = nullptr;
    other.m_writes_to = nullptr;
  }

  ~Conn()
  {
    SSL_free(m_ssl);
  }

  void set_sni(const char *hostname)
  {
    int err;
    err = SSL_set_tlsext_host_name(m_ssl, hostname);
    assert(err == 1);
  }

  void set_session(SSL_SESSION *sess)
  {
    int err = SSL_set_session(m_ssl, sess);
    assert(err == 1);
  }

  void ragged_close()
  {
    SSL_set_shutdown(m_ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
  }

  SSL_SESSION * get_session()
  {
    ragged_close();
    return SSL_get1_session(m_ssl);
  }

  bool connect()
  {
    return chkerr(SSL_get_error(m_ssl, SSL_connect(m_ssl)));
  }

  bool accept()
  {
    return chkerr(SSL_get_error(m_ssl, SSL_accept(m_ssl)));
  }

  void transfer_to(Conn &other)
  {
    uint8_t buf[262144] = { 0 };

    while (true)
    {
      int err = BIO_read(m_writes_to, buf, sizeof(buf));

      if (err == 0 || err == -1)
      {
        break;
      } else if (err > 0) {
        BIO_write(other.m_reads_from, buf, err);
      }
    }
  }

  void dump_cipher()
  {
    printf("negotiated %s with %s\n",
           SSL_get_cipher_version(m_ssl),
           SSL_get_cipher(m_ssl));
  }

  void write(const uint8_t *buf, size_t n)
  {
    chkerr(SSL_get_error(m_ssl,
                         SSL_write(m_ssl, buf, n)));
  }

  void read(uint8_t *buf, size_t n)
  {
    while (n)
    {
      int rd = SSL_read(m_ssl, buf, n);

      assert(rd >= 0);
      buf += rd;
      n -= rd;
    }
  }
};

static bool do_handshake_step(Conn &client, Conn &server)
{
  bool s_connected = server.accept();
  bool c_connected = client.connect();

  if (s_connected && c_connected)
  {
    return false;
  }

  client.transfer_to(server);
  server.transfer_to(client);
  return true;
}

static void do_handshake(Conn &client, Conn &server)
{
  client.set_sni("localhost");

  while (do_handshake_step(client, server)) {}
}

static size_t apply_work_multiplier(size_t work)
{
  const char *multiplier = getenv("BENCH_MULTIPLIER");
  if (multiplier) {
    return size_t(work * atof(multiplier));
  }
  return work;
}

static double get_time()
{
  timeval tv;
  gettimeofday(&tv, NULL);

  double v = tv.tv_sec;
  v += double(tv.tv_usec) / 1.e6;
  return v;
}

static void test_bulk(Context &server_ctx, Context &client_ctx,
                      const size_t plaintext_size)
{
  Conn server(server_ctx.open());
  Conn client(client_ctx.open());

  do_handshake(client, server);
  client.dump_cipher();

  std::vector<uint8_t> plaintext(plaintext_size, 0);
  double time_send = 0;
  double time_recv = 0;
  const size_t total_data = apply_work_multiplier(
      plaintext_size < 8192 ? (64 * 1024 * 1024) : (1024 * 1024 * 1024)
  );
  const size_t rounds = total_data / plaintext_size;

  for (size_t i = 0; i < rounds; i++)
  {
    double t = get_time();
    server.write(&plaintext[0], plaintext.size());
    time_send += get_time() - t;

    server.transfer_to(client);
    t = get_time();
    client.read(&plaintext[0], plaintext.size());
    time_recv += get_time() - t;
  }

  const double total_mbs = (plaintext_size * rounds) / (1024. * 1024.);
  printf("send: %g MB/s\n", total_mbs / time_send);
  printf("recv: %g MB/s\n", total_mbs / time_recv);
}

static void test_handshake(Context &server_ctx, Context &client_ctx)
{
  double time_client = 0;
  double time_server = 0;

  const size_t handshakes = apply_work_multiplier(512);

  for (size_t i = 0; i < handshakes; i++) {
    Conn server(server_ctx.open());
    Conn client(client_ctx.open());

    client.set_sni("localhost");

    double t;

    t = get_time();
    client.connect();
    client.transfer_to(server);
    time_client += get_time() - t;

    t = get_time();
    server.accept();
    server.transfer_to(client);
    time_server += get_time() - t;

    t = get_time();
    client.connect();
    client.transfer_to(server);
    time_client += get_time() - t;

    t = get_time();
    server.accept();
    server.transfer_to(client);
    time_server += get_time() - t;

    assert(server.accept());
    assert(client.accept());
  }

  printf("handshakes\tclient\t%g\thandshakes/s\n",
         double(handshakes) / time_client);
  printf("handshakes\tserver\t%g\thandshakes/s\n",
         double(handshakes) / time_server);
}

static void test_handshake_resume(Context &server_ctx, Context &client_ctx,
                                  const bool with_tickets)
{
  double time_client = 0;
  double time_server = 0;

  const size_t handshakes = apply_work_multiplier(4096);

  server_ctx.enable_resume();
  client_ctx.enable_resume();

  if (!with_tickets) {
    server_ctx.disable_tickets();
    client_ctx.disable_tickets();
  }

  SSL_SESSION *client_session;

  {
    Conn initial_server(server_ctx.open());
    Conn initial_client(client_ctx.open());
    initial_client.set_sni("localhost");
    do_handshake(initial_client, initial_server);

    // pass some data to ensure ticket receipt
    initial_server.write((const uint8_t *) "hello", 5);
    initial_server.transfer_to(initial_client);

    uint8_t buf[5];
    initial_client.read(buf, 5);

    client_session = initial_client.get_session();
    assert(SSL_SESSION_is_resumable(client_session));
    initial_client.dump_cipher();
    initial_server.ragged_close();
  }

  client_ctx.bodge_disable_resume();

  for (size_t i = 0; i < handshakes; i++) {
    Conn server(server_ctx.open());
    Conn client(client_ctx.open());

    client.set_sni("localhost");
    client.set_session(client_session);
    assert(SSL_SESSION_is_resumable(client_session));

    double t;

    t = get_time();
    client.connect();
    client.transfer_to(server);
    time_client += get_time() - t;

    t = get_time();
    server.accept();
    server.transfer_to(client);
    time_server += get_time() - t;

    t = get_time();
    client.connect();
    client.transfer_to(server);
    time_client += get_time() - t;

    t = get_time();
    server.accept();
    server.transfer_to(client);
    time_server += get_time() - t;

    assert(server.accept());
    assert(client.connect());
    server.ragged_close();
    client.ragged_close();
  }

  server_ctx.dump_sess_stats();

  printf("handshakes\tclient\t%g\thandshakes/s\n",
         double(handshakes) / time_client);
  printf("handshakes\tserver\t%g\thandshakes/s\n",
         double(handshakes) / time_server);
}

static void test_memory(Context &server_ctx, Context &client_ctx,
                        size_t session_count)
{
  std::vector<Conn> servers;
  std::vector<Conn> clients;

  session_count /= 2;

  servers.reserve(session_count);
  clients.reserve(session_count);

  for (size_t i = 0; i < session_count; i++) {
    servers.push_back(std::move(server_ctx.open()));
    clients.push_back(std::move(client_ctx.open()));
    clients.back().set_sni("localhost");
  }

  for (size_t s = 0; s < 5; s++) {
    for (size_t i = 0; i < session_count; i++) {
      do_handshake_step(clients[i], servers[i]);
    }
  }

  for (size_t i = 0; i < session_count; i++) {
    uint8_t buf[1024] = { 0 };
    clients[i].write(buf, sizeof buf);
  }

  for (size_t i = 0; i < session_count; i++) {
    clients[i].transfer_to(servers[i]);
    uint8_t buf[1024];
    servers[i].read(buf, sizeof buf);
  }
}

static int usage()
{
  puts("usage: bench <handshake|handshake-resume|handshake-ticket> <suite>");
  puts("usage: bench bulk <suite> <plaintext-size>");
  return 1;
}

int main(int argc, char **argv)
{
  Context server_ctx = Context::server();
  Context client_ctx = Context::client();

  if (argc < 3) {
    return usage();
  }

  server_ctx.set_ciphers(argv[2]);
  client_ctx.set_ciphers(argv[2]);
  server_ctx.load_server_creds();
  client_ctx.load_client_creds();

  if (!strcmp(argv[1], "bulk") && argc == 4) {
    test_bulk(server_ctx, client_ctx, atoi(argv[3]));
  } else if (!strcmp(argv[1], "handshake")) {
    test_handshake(server_ctx, client_ctx);
  } else if (!strcmp(argv[1], "handshake-resume")) {
    test_handshake_resume(server_ctx, client_ctx, false);
  } else if (!strcmp(argv[1], "handshake-ticket")) {
    test_handshake_resume(server_ctx, client_ctx, true);
  } else if (!strcmp(argv[1], "memory")) {
    test_memory(server_ctx, client_ctx, atoi(argv[3]));
  } else {
    return usage();
  }

  return 0;
}
