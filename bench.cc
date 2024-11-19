#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <sys/time.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <atomic>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

static bool chkerr(int err) {
  if (err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL) {
    ERR_print_errors_fp(stdout);
    puts("error");
    exit(1);
    return true;
  }
  return err == 0;
}

enum class KeyType {
  RSA2048 = 0,
  ECDSAP256 = 1,
};

static int new_session_cb(SSL *ssl, SSL_SESSION *sess);

class Context {
  ssl_ctx_st *m_ctx;

public:
  Context(ssl_ctx_st *ctx) : m_ctx(ctx) {
    SSL_CTX_set_options(m_ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
  }

  ~Context() { SSL_CTX_free(m_ctx); }

  ssl_st *open() { return SSL_new(m_ctx); }

  void load_server_creds(const KeyType which) {
    int err;

    switch (which) {
    case KeyType::RSA2048:
      err = SSL_CTX_use_certificate_chain_file(
          m_ctx, "../rustls/test-ca/rsa-2048/end.fullchain");
      assert(err == 1);
      err = SSL_CTX_use_PrivateKey_file(
          m_ctx, "../rustls/test-ca/rsa-2048/end.key", SSL_FILETYPE_PEM);
      assert(err == 1);
      break;
    case KeyType::ECDSAP256:
      err = SSL_CTX_use_certificate_chain_file(
          m_ctx, "../rustls/test-ca/ecdsa-p256/end.fullchain");
      assert(err == 1);
      err = SSL_CTX_use_PrivateKey_file(
          m_ctx, "../rustls/test-ca/ecdsa-p256/end.key", SSL_FILETYPE_PEM);
      assert(err == 1);
      break;
    }
  }

  void load_client_creds(const KeyType which) {
    int err;
    switch (which) {
    case KeyType::RSA2048:
      err = SSL_CTX_load_verify_locations(
          m_ctx, "../rustls/test-ca/rsa-2048/ca.cert", NULL);
      break;
    case KeyType::ECDSAP256:
      err = SSL_CTX_load_verify_locations(
          m_ctx, "../rustls/test-ca/ecdsa-p256/ca.cert", NULL);
      break;
    }
    assert(err == 1);
  }

  void set_version(int minversion, int maxversion) {
    SSL_CTX_set_min_proto_version(m_ctx, minversion);
    SSL_CTX_set_max_proto_version(m_ctx, maxversion);
  }

  bool is_tls13() const {
    return SSL_CTX_get_max_proto_version(m_ctx) == TLS1_3_VERSION;
  }

  void set_ciphers(const char *ciphers) {
    if (!strcmp(ciphers, "TLS_AES_128_GCM_SHA256") ||
        !strcmp(ciphers, "TLS_AES_256_GCM_SHA384") ||
        !strcmp(ciphers, "TLS_CHACHA20_POLY1305_SHA256")) {
      set_version(TLS1_3_VERSION, TLS1_3_VERSION);
#ifndef BORINGSSL
      SSL_CTX_set_ciphersuites(m_ctx, ciphers);
#else
      // boringssl does not have any direct way to configure TLS1.3 cipher
      // suites. however, it does have "compliance policies" which give limited
      // control over their order, and a configuration switch for pretending
      // hardware-accelerated AES is absent -- which prioritises chacha.
      //
      // So we can arrange for one ciphersuite, as follows:
      //
      // - TLS_CHACHA20_POLY1305_SHA256:
      // `SSL_CTX_set_aes_hw_override_for_testing(ctx, false)`
      // - TLS_AES_128_GCM_SHA256: the default
      // - TLS_AES_256_GCM_SHA384: `SSL_CTX_set_compliance_policy(ctx,
      // ssl_compliance_policy_cnsa_202407)`
      if (!strcmp(ciphers, "TLS_AES_256_GCM_SHA384")) {
        SSL_CTX_set_compliance_policy(m_ctx, ssl_compliance_policy_cnsa_202407);
      } else if (!strcmp(ciphers, "TLS_CHACHA20_POLY1305_SHA256")) {
        bssl::SSL_CTX_set_aes_hw_override_for_testing(m_ctx, false);
      } else {
        assert(!strcmp(ciphers, "TLS_AES_128_GCM_SHA256"));
      }
#endif
    } else {
      set_version(TLS1_2_VERSION, TLS1_2_VERSION);
      SSL_CTX_set_cipher_list(m_ctx, ciphers);
    }
  }

  void enable_resume() {
    SSL_CTX_sess_set_new_cb(m_ctx, new_session_cb);
    SSL_CTX_set_session_cache_mode(m_ctx, SSL_SESS_CACHE_BOTH);
    SSL_CTX_set_session_id_context(m_ctx, (const uint8_t *)"localhost",
                                   strlen("localhost"));
  }

  void bodge_disable_resume() {
    // To allow ticket reuse, pretend we're not caching client sessions
    SSL_CTX_set_session_cache_mode(m_ctx, SSL_SESS_CACHE_SERVER);
  }

  void disable_tickets() {
    long opts = SSL_CTX_get_options(m_ctx);
    SSL_CTX_set_options(m_ctx, opts | SSL_OP_NO_TICKET);
  }

  void dump_sess_stats() {
    printf(
        "connects: %ld, connects-good: %ld, accepts: %ld, accepts-good: %ld\n",
        long(SSL_CTX_sess_connect(m_ctx)),
        long(SSL_CTX_sess_connect_good(m_ctx)),
        long(SSL_CTX_sess_accept(m_ctx)),
        long(SSL_CTX_sess_accept_good(m_ctx)));
    printf("sessions: %ld, hits: %ld, misses: %ld\n",
           long(SSL_CTX_sess_number(m_ctx)), long(SSL_CTX_sess_hits(m_ctx)),
           long(SSL_CTX_sess_misses(m_ctx)));
  }

  static Context server() { return Context(SSL_CTX_new(TLS_server_method())); }

  static Context client() { return Context(SSL_CTX_new(TLS_client_method())); }
};

class Conn {
  ssl_st *m_ssl;
  std::vector<uint8_t> m_read_buffer; // borrowed by m_reads_from, thence m_ssl
  bio_st *m_reads_from;               // owned by m_ssl
  bio_st *m_writes_to;                // owned by m_ssl
  SSL_SESSION *m_one_session;         // maybe null, owned by us

  Conn(const Conn &) = delete;
  Conn &operator=(const Conn &) = delete;

public:
  Conn(ssl_st *ssl)
      : m_ssl(ssl), m_reads_from(nullptr), m_writes_to(BIO_new(BIO_s_mem())),
        m_one_session(nullptr) {
    install_read_bio();
    SSL_set0_wbio(m_ssl, m_writes_to);
    SSL_set_app_data(m_ssl, this);
  }

  Conn(Conn &&other)
      : m_ssl(other.m_ssl), m_reads_from(nullptr),
        m_writes_to(other.m_writes_to), m_one_session(other.m_one_session) {
    SSL_set_app_data(m_ssl, this);
    other.m_ssl = nullptr;
    m_read_buffer.swap(other.m_read_buffer);
    install_read_bio();
    other.m_writes_to = nullptr;
    other.m_one_session = nullptr;
  }

  ~Conn() {
    SSL_SESSION_free(m_one_session);
    SSL_free(m_ssl);
  }

  void install_read_bio() {
    static uint8_t empty_buf[0] = {};
    m_reads_from =
        BIO_new_mem_buf(m_read_buffer.data() ? m_read_buffer.data() : empty_buf,
                        m_read_buffer.size());
    assert(m_reads_from != nullptr);
    BIO_set_mem_eof_return(m_reads_from, -1);
    SSL_set0_rbio(m_ssl, m_reads_from); // frees previous m_reads_from
  }

  int save_one_session(SSL_SESSION *sess) {
    if (m_one_session == nullptr) {
      m_one_session = sess;
      return 1;
    }
    return 0;
  }

  void set_sni(const char *hostname) {
    int err;
    err = SSL_set_tlsext_host_name(m_ssl, hostname);
    assert(err == 1);
  }

  void set_session(SSL_SESSION *sess) {
    int err = SSL_set_session(m_ssl, sess);
    assert(err == 1);
  }

  void ragged_close() {
    SSL_set_shutdown(m_ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
  }

  SSL_SESSION *get_session() {
    ragged_close();
    if (m_one_session) {
      SSL_SESSION_up_ref(m_one_session);
      return m_one_session;
    }
    return SSL_get1_session(m_ssl);
  }

  bool was_resumed() { return SSL_session_reused(m_ssl) == 1; }

  bool connect() { return chkerr(SSL_get_error(m_ssl, SSL_connect(m_ssl))); }

  bool accept() { return chkerr(SSL_get_error(m_ssl, SSL_accept(m_ssl))); }

  void transfer_to(Conn &other) {
    uint8_t buf[262144] = {0};

    bool new_bytes = false;

    while (true) {
      int err = BIO_read(m_writes_to, buf, sizeof(buf));

      if (err == 0 || err == -1) {
        break;
      } else if (err > 0) {
        if (!new_bytes) {
          other.drop_read_bytes();
          new_bytes = true;
        }

        other.m_read_buffer.insert(other.m_read_buffer.end(), buf, buf + err);
      }
    }

    if (new_bytes) {
      other.install_read_bio();
    }
  }

  void drop_read_bytes() {
    // eliminate processed bytes from read buffer
    char *old_buf = nullptr;
    long old_len = BIO_get_mem_data(m_reads_from, &old_buf);
    long consumed = m_read_buffer.size() - old_len;
    m_read_buffer.erase(m_read_buffer.begin(),
                        m_read_buffer.begin() + consumed);
    // caller _MUST_ now call install_read_bio() prior to touching
    // m_ssl
  }

  std::string get_cipher_string() {
    std::string r;
    r += SSL_get_cipher_version(m_ssl);
    r += '\t';
    r += SSL_get_cipher(m_ssl);
    return r;
  }

  void write(const uint8_t *buf, size_t n) {
    chkerr(SSL_get_error(m_ssl, SSL_write(m_ssl, buf, n)));
  }

  void read(uint8_t *buf, size_t n) {
    while (n) {
      int rd = SSL_read(m_ssl, buf, n);

      assert(rd >= 0);
      buf += rd;
      n -= rd;
    }
  }
};

static int new_session_cb(SSL *ssl, SSL_SESSION *sess) {
  Conn *conn = (Conn *)SSL_get_app_data(ssl);
  if (conn) {
    return conn->save_one_session(sess);
  }
  return 0;
}

static bool do_handshake_step(Conn &client, Conn &server) {
  bool s_connected = server.accept();
  bool c_connected = client.connect();

  if (s_connected && c_connected) {
    return false;
  }

  client.transfer_to(server);
  server.transfer_to(client);
  return true;
}

static void do_handshake(Conn &client, Conn &server) {
  client.set_sni("localhost");

  while (do_handshake_step(client, server)) {
  }
}

static size_t apply_work_multiplier(size_t work) {
  const char *multiplier = getenv("BENCH_MULTIPLIER");
  if (multiplier) {
    return size_t(work * atof(multiplier));
  }
  return work;
}

static double get_time() {
  timeval tv;
  gettimeofday(&tv, NULL);

  double v = tv.tv_sec;
  v += double(tv.tv_usec) / 1.e6;
  return v;
}

struct Timings {
  std::atomic<double> client;
  std::atomic<double> server;

  Timings() : client(0.), server(0.) {}
};

class LatencyOutput {
  FILE *m_output;

public:
  LatencyOutput(const char *which) : m_output(nullptr) {
    const char *file_prefix = getenv("BENCH_LATENCY");
    if (file_prefix) {
      std::ostringstream thread_id;
      thread_id << std::this_thread::get_id();
      char filename[128] = {0};
      snprintf(filename, sizeof(filename), "%s-%s-%s-latency.tsv", file_prefix,
               which, thread_id.str().c_str());
      m_output = fopen(filename, "w+");
    }
  }

  ~LatencyOutput() {
    if (m_output) {
      fclose(m_output);
      m_output = nullptr;
    }
  }

  void sample(double t) {
    if (!m_output) {
      return;
    }

    fprintf(m_output, "%.8f\t%.8f\n", get_time(), t * 1e6);
  }
};

static size_t rounds_for_bulk_test(const size_t plaintext_size) {

  const size_t total_data = apply_work_multiplier(
      plaintext_size < 8192 ? (64 * 1024 * 1024) : (1024 * 1024 * 1024));
  const size_t rounds = total_data / plaintext_size;
  return rounds;
}

static void test_bulk_one(Timings &timings_out, Context &server_ctx,
                          Context &client_ctx, const size_t rounds,
                          const size_t plaintext_size) {
  Conn server(server_ctx.open());
  Conn client(client_ctx.open());

  do_handshake(client, server);

  std::vector<uint8_t> plaintext(plaintext_size, 0);
  double time_send = 0;
  double time_recv = 0;

  for (size_t i = 0; i < rounds; i++) {
    double t = get_time();
    server.write(&plaintext[0], plaintext.size());
    time_send += get_time() - t;

    server.transfer_to(client);
    t = get_time();
    client.read(&plaintext[0], plaintext.size());
    time_recv += get_time() - t;
  }

  timings_out.server.store(time_send);
  timings_out.client.store(time_recv);
}

static void print_results(const char *server, const char *client,
                          const std::vector<Timings> &thread_timings,
                          const double thread_work, const char *units) {
  const size_t n_threads = thread_timings.size();
  if (n_threads > 1) {
    printf("%s\tthreads\t%zu\t", server, n_threads);
    double total_server = 0.;

    for (unsigned i = 0; i < n_threads; i++) {
      const double server = thread_work / thread_timings[i].server.load();
      total_server += server;
      printf("%g\t", server);
    }
    printf("total\t%g\tper-thread\t%g\t%s\n", total_server,
           total_server / n_threads, units);
    printf("%s\tthreads\t%zu\t", client, n_threads);
    double total_client = 0.;

    for (unsigned i = 0; i < n_threads; i++) {
      const double client = thread_work / thread_timings[i].client.load();
      total_client += client;
      printf("%g\t", client);
    }
    printf("total\t%g\tper-thread\t%g\t%s\n", total_client,
           total_client / n_threads, units);
  } else {
    printf("%s\t%g\t%s\n", server,
           thread_work / thread_timings[0].server.load(), units);
    printf("%s\t%g\t%s\n", client,
           thread_work / thread_timings[0].client.load(), units);
  }
}

static void test_bulk(const unsigned n_threads, Context &server_ctx,
                      Context &client_ctx, const size_t plaintext_size) {

  std::vector<std::thread> threads;
  std::vector<Timings> results(n_threads);
  const size_t rounds = rounds_for_bulk_test(plaintext_size);

  for (unsigned i = 0; i < n_threads; i++) {
    threads.push_back(std::thread(&test_bulk_one, std::ref(results[i]),
                                  std::ref(server_ctx), std::ref(client_ctx),
                                  rounds, plaintext_size));
  }

  for (unsigned i = 0; i < n_threads; i++) {
    threads[i].join();
  }

  Conn client(client_ctx.open());
  Conn server(server_ctx.open());
  do_handshake(client, server);
  std::string prefix_send = "bulk\tsend\t";
  std::string prefix_recv = "bulk\trecv\t";
  prefix_send += client.get_cipher_string();
  prefix_recv += client.get_cipher_string();

  const double total_mbs = (plaintext_size * rounds) / (1024. * 1024.);
  print_results(prefix_send.c_str(), prefix_recv.c_str(), results, total_mbs,
                "MB/s");
}

static void test_handshake_one(Timings &timings_out, const unsigned handshakes,
                               Context &server_ctx, Context &client_ctx) {
  double time_client = 0;
  double time_server = 0;

  LatencyOutput client_latency("client");
  LatencyOutput server_latency("server");

  for (size_t i = 0; i < handshakes; i++) {
    Conn server(server_ctx.open());
    Conn client(client_ctx.open());

    client.set_sni("localhost");

    double t, time_client_one = 0, time_server_one = 0;

    t = get_time();
    client.connect();
    client.transfer_to(server);
    time_client_one += get_time() - t;

    t = get_time();
    server.accept();
    server.transfer_to(client);
    time_server_one += get_time() - t;

    t = get_time();
    client.connect();
    client.transfer_to(server);
    time_client_one += get_time() - t;

    t = get_time();
    server.accept();
    server.transfer_to(client);
    time_server_one += get_time() - t;

    client_latency.sample(time_client_one);
    server_latency.sample(time_server_one);
    time_client += time_client_one;
    time_server += time_server_one;

    assert(server.accept());
    assert(client.connect());
    assert(!server.was_resumed());
    assert(!client.was_resumed());
  }

  timings_out.client.store(time_client);
  timings_out.server.store(time_server);
}

static void test_handshake(const unsigned n_threads, Context &server_ctx,
                           Context &client_ctx) {
  std::vector<std::thread> threads;
  std::vector<Timings> results(n_threads);
  const size_t handshakes = apply_work_multiplier(512);

  for (unsigned i = 0; i < n_threads; i++) {
    threads.push_back(std::thread(&test_handshake_one, std::ref(results[i]),
                                  handshakes, std::ref(server_ctx),
                                  std::ref(client_ctx)));
  }

  for (unsigned i = 0; i < n_threads; i++) {
    threads[i].join();
  }

  Conn client(client_ctx.open());
  Conn server(server_ctx.open());
  do_handshake(client, server);
  std::string prefix_server = "handshakes\tserver\t";
  std::string prefix_client = "handshakes\tclient\t";
  prefix_server += client.get_cipher_string();
  prefix_client += client.get_cipher_string();

  print_results(prefix_server.c_str(), prefix_client.c_str(), results,
                handshakes, "handshakes/s");
}

static void test_handshake_resume_one(Timings &timings_out, Context &server_ctx,
                                      Context &client_ctx,
                                      SSL_SESSION *client_session,
                                      const size_t handshakes) {
  double time_client = 0;
  double time_server = 0;

  LatencyOutput client_latency("client");
  LatencyOutput server_latency("server");

  for (size_t i = 0; i < handshakes; i++) {
    Conn server(server_ctx.open());
    Conn client(client_ctx.open());

    client.set_sni("localhost");
    client.set_session(client_session);
    assert(SSL_SESSION_is_resumable(client_session));

    double t, time_client_one = 0, time_server_one = 0;

    t = get_time();
    client.connect();
    client.transfer_to(server);
    time_client_one += get_time() - t;

    t = get_time();
    server.accept();
    server.transfer_to(client);
    time_server_one += get_time() - t;

    t = get_time();
    client.connect();
    client.transfer_to(server);
    time_client_one += get_time() - t;

    t = get_time();
    server.accept();
    server.transfer_to(client);
    time_server_one += get_time() - t;

    assert(server.accept());
    assert(client.connect());
    assert(server.was_resumed());
    assert(client.was_resumed());
    server.ragged_close();
    client.ragged_close();

    client_latency.sample(time_client_one);
    server_latency.sample(time_server_one);
    time_client += time_client_one;
    time_server += time_server_one;
  }

  timings_out.client.store(time_client);
  timings_out.server.store(time_server);
}

static void test_handshake_resume(const unsigned n_threads, Context &server_ctx,
                                  Context &client_ctx,
                                  const bool with_tickets) {
  const size_t handshakes = apply_work_multiplier(4096);

  server_ctx.enable_resume();
  client_ctx.enable_resume();

  std::string prefix_server, prefix_client;

  if (!with_tickets) {
    server_ctx.disable_tickets();
    client_ctx.disable_tickets();
    prefix_server = "handshake-resume\tserver\t";
    prefix_client = "handshake-resume\tclient\t";

#ifdef BORINGSSL
    if (server_ctx.is_tls13()) {
      printf("!!! BoringSSL does not support stateful resumption for TLS1.3\n");
      return;
    }
#endif
  } else {
    prefix_server = "handshake-ticket\tserver\t";
    prefix_client = "handshake-ticket\tclient\t";
  }

  SSL_SESSION *client_session;

  {
    Conn initial_server(server_ctx.open());
    Conn initial_client(client_ctx.open());
    initial_client.set_sni("localhost");
    do_handshake(initial_client, initial_server);

    // pass some data to ensure ticket receipt
    initial_server.write((const uint8_t *)"hello", 5);
    initial_server.transfer_to(initial_client);

    uint8_t buf[5];
    initial_client.read(buf, 5);

    client_session = initial_client.get_session();
    assert(SSL_SESSION_is_resumable(client_session));
    initial_server.ragged_close();

    prefix_server += initial_client.get_cipher_string();
    prefix_client += initial_client.get_cipher_string();
  }

  client_ctx.bodge_disable_resume();

  std::vector<std::thread> threads;
  std::vector<Timings> results(n_threads);

  for (unsigned i = 0; i < n_threads; i++) {
    threads.push_back(std::thread(
        &test_handshake_resume_one, std::ref(results[i]), std::ref(server_ctx),
        std::ref(client_ctx), client_session, handshakes));
  }

  for (unsigned i = 0; i < n_threads; i++) {
    threads[i].join();
  }

  server_ctx.dump_sess_stats();
  print_results(prefix_server.c_str(), prefix_client.c_str(), results,
                handshakes, "handshakes/s");
}

static void test_memory(Context &server_ctx, Context &client_ctx,
                        size_t session_count) {
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
    uint8_t buf[1024] = {0};
    clients[i].write(buf, sizeof buf);
  }

  for (size_t i = 0; i < session_count; i++) {
    clients[i].transfer_to(servers[i]);
    uint8_t buf[1024];
    servers[i].read(buf, sizeof buf);
  }
}

static int usage() {
  puts("usage: bench [--threads N] [--rsa|--ecdsa] "
       "<handshake|handshake-resume|handshake-ticket> <suite>");
  puts("usage: bench [--threads N] bulk <suite> <plaintext-size>");
  puts("usage: bench memory <count>");
  return 1;
}

int main(int argc, char **argv) {
  Context server_ctx = Context::server();
  Context client_ctx = Context::client();

  argv += 1;
  argc -= 1;

  if (argc < 2) {
    return usage();
  }

  unsigned n_threads = 1;
  if (strcmp(argv[0], "--threads") == 0) {
    n_threads = unsigned(atoi(argv[1]));
    argv += 2;
    argc -= 2;
    if (n_threads == 0) {
      puts("bad --threads count");
      return usage();
    }
  }

  KeyType key_type;
  if (strcmp(argv[0], "--rsa") == 0) {
    key_type = KeyType::RSA2048;
    argv += 1;
    argc -= 1;
  } else if (strcmp(argv[0], "--ecdsa") == 0) {
    key_type = KeyType::ECDSAP256;
    argv += 1;
    argc -= 1;
  } else {
    key_type = KeyType::RSA2048;
  }

  if (argc < 2) {
    return usage();
  }

  server_ctx.set_ciphers(argv[1]);
  client_ctx.set_ciphers(argv[1]);
  server_ctx.load_server_creds(key_type);
  client_ctx.load_client_creds(key_type);

  if (!strcmp(argv[0], "bulk") && argc == 3) {
    test_bulk(n_threads, server_ctx, client_ctx, atoi(argv[2]));
  } else if (!strcmp(argv[0], "handshake")) {
    test_handshake(n_threads, server_ctx, client_ctx);
  } else if (!strcmp(argv[0], "handshake-resume")) {
    test_handshake_resume(n_threads, server_ctx, client_ctx, false);
  } else if (!strcmp(argv[0], "handshake-ticket")) {
    test_handshake_resume(n_threads, server_ctx, client_ctx, true);
  } else if (!strcmp(argv[0], "memory")) {
    test_memory(server_ctx, client_ctx, atoi(argv[2]));
  } else {
    return usage();
  }

  return 0;
}
