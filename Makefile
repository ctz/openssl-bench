#CXXFLAGS+=-g -Wall -Werror -O3 -std=c++17
CXXFLAGS+=-g -Wall -Werror -O0 -std=c++17

LDLIBS+=-ldl -lpthread
MEMUSAGE=/usr/bin/time -f %M

AWSLC_LDFLAGS=-L$(AWS_INSTALL_PREFIX)/lib
AWSLC_LDLIBS=$(LDLIBS) -lssl -lcrypto
AWSLC_CXXFLAGS=$(CXXFLAGS) -DWITH_AWS -I$(AWS_INSTALL_PREFIX)/include
bench-aws-lc: bench.cc
	$(CXX) $(AWSLC_CXXFLAGS) $< -o bench $(AWSLC_LDFLAGS) $(AWSLC_LDLIBS)

BORINGSSL_LDFLAGS=-L$(BORINGSSL_INSTALL_PREFIX)/lib
BORINGSSL_LDLIBS=$(LDLIBS) -lssl -lcrypto
BORINGSSL_CXXFLAGS=$(CXXFLAGS) -DWITH_BORINGSSL -I$(BORINGSSL_INSTALL_PREFIX)/include
bench-boringssl: bench.cc
	$(CXX) $(BORINGSSL_CXXFLAGS) $< -o bench $(BORINGSSL_LDFLAGS) $(BORINGSSL_LDLIBS)

LIBRESSL_LDFLAGS=-L$(LIBRESSL_INSTALL_PREFIX)/lib
LIBRESSL_LDLIBS=$(LDLIBS) -lssl -lcrypto
LIBRESSL_CXXFLAGS=$(CXXFLAGS) -DWITH_LIBRESSL -I$(LIBRESSL_INSTALL_PREFIX)/include
bench-libressl: bench.cc
	$(CXX) $(LIBRESSL_CXXFLAGS) $< -o bench $(LIBRESSL_LDFLAGS) $(LIBRESSL_LDLIBS)

OPENSSL_LDFLAGS=-L$(OPENSSL_INSTALL_PREFIX)/lib
OPENSSL_LDLIBS=$(LDLIBS) -lssl -lcrypto
OPENSSL_CXXFLAGS=$(CXXFLAGS) -DWITH_OPENSSL -I$(OPENSSL_INSTALL_PREFIX)/include
bench-openssl: bench.cc
	$(CXX) $(OPENSSL_CXXFLAGS) $< -o bench $(OPENSSL_LDFLAGS) $(OPENSSL_LDLIBS)

WOLFSSL_LDFLAGS=-L$(WOLFSSL_INSTALL_PREFIX)/lib
WOLFSSL_LDLIBS=$(LDLIBS) -lwolfssl
WOLFSSL_CXXFLAGS=$(CXXFLAGS) -DWITH_WOLFSSL -I$(WOLFSSL_INSTALL_PREFIX)/include/wolfssl
WOLFSSL_CXXFLAGS+=-I$(WOLFSSL_INSTALL_PREFIX)/include/
bench-wolfssl: bench.cc
	$(CXX) $(WOLFSSL_CXXFLAGS) $< -o bench $(WOLFSSL_LDFLAGS) $(WOLFSSL_LDLIBS)


perf.data: bench
	$(ENV) perf record -F9999 --call-graph dwarf -- ./bench bulk ECDHE-RSA-AES128-GCM-SHA256 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > perf-aes128-openssl.svg

extra:
	perf record -F9999 --call-graph dwarf -- $(ENV) ./bench bulk ECDHE-RSA-AES256-GCM-SHA384 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > perf-aes256-openssl.svg
	perf record -F9999 --call-graph dwarf -- $(ENV) ./bench bulk ECDHE-RSA-CHACHA20-POLY1305 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > perf-chacha-openssl.svg
	perf record -F9999 --call-graph dwarf -- $(ENV) ./bench handshake ECDHE-RSA-AES256-GCM-SHA384
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > perf-fullhs-openssl.svg
	perf record -F9999 --call-graph dwarf -- $(ENV) ./bench handshake-resume ECDHE-RSA-AES256-GCM-SHA384
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > perf-resume-openssl.svg
	perf record -F9999 --call-graph dwarf -- $(ENV) ./bench handshake-ticket ECDHE-RSA-AES256-GCM-SHA384
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > perf-ticket-openssl.svg

measure-aws:
	$(ENV) ./bench bulk ECDHE-RSA-AES128-GCM-SHA256 1048576
	$(ENV) ./bench bulk ECDHE-RSA-AES256-GCM-SHA384 1048576
	$(ENV) ./bench bulk ECDHE-RSA-CHACHA20-POLY1305 1048576
	$(ENV) ./bench bulk TLS_AES_256_GCM_SHA384 1048576
	$(ENV) ./bench handshake ECDHE-RSA-AES256-GCM-SHA384
	$(ENV) ./bench handshake-resume ECDHE-RSA-AES256-GCM-SHA384
	$(ENV) ./bench handshake-ticket ECDHE-RSA-AES256-GCM-SHA384
	$(ENV) ./bench handshake TLS_AES_256_GCM_SHA384
	#$(ENV) ./bench handshake-resume TLS_AES_256_GCM_SHA384
	$(ENV) ./bench handshake-ticket TLS_AES_256_GCM_SHA384
	$(ENV) ./bench --ecdsa handshake ECDHE-ECDSA-AES256-GCM-SHA384
	$(ENV) ./bench --ecdsa handshake TLS_AES_256_GCM_SHA384

measure-wolfssl: bench
	$(ENV) ./bench bulk ECDHE-RSA-AES128-GCM-SHA256 1048576
	$(ENV) ./bench bulk ECDHE-RSA-AES256-GCM-SHA384 1048576
	$(ENV) ./bench bulk ECDHE-RSA-CHACHA20-POLY1305 1048576
	#$(ENV) ./bench bulk TLS_AES_256_GCM_SHA384 1048576
	$(ENV) ./bench handshake ECDHE-RSA-AES256-GCM-SHA384
	$(ENV) ./bench handshake-resume ECDHE-RSA-AES256-GCM-SHA384
	$(ENV) ./bench handshake-ticket ECDHE-RSA-AES256-GCM-SHA384
	#$(ENV) ./bench handshake TLS_AES_256_GCM_SHA384
	#$(ENV) ./bench handshake-resume TLS_AES_256_GCM_SHA384
	#$(ENV) ./bench handshake-ticket TLS_AES_256_GCM_SHA384
	#$(ENV) ./bench --ecdsa handshake ECDHE-ECDSA-AES256-GCM-SHA384
	#$(ENV) ./bench --ecdsa handshake TLS_AES_256_GCM_SHA384

measure: bench
	$(ENV) ./bench bulk ECDHE-RSA-AES128-GCM-SHA256 1048576
	$(ENV) ./bench bulk ECDHE-RSA-AES256-GCM-SHA384 1048576
	$(ENV) ./bench bulk ECDHE-RSA-CHACHA20-POLY1305 1048576
	$(ENV) ./bench bulk TLS_AES_256_GCM_SHA384 1048576
	$(ENV) ./bench handshake ECDHE-RSA-AES256-GCM-SHA384
	$(ENV) ./bench handshake-resume ECDHE-RSA-AES256-GCM-SHA384
	$(ENV) ./bench handshake-ticket ECDHE-RSA-AES256-GCM-SHA384
	$(ENV) ./bench handshake TLS_AES_256_GCM_SHA384
	$(ENV) ./bench handshake-resume TLS_AES_256_GCM_SHA384
	$(ENV) ./bench handshake-ticket TLS_AES_256_GCM_SHA384
	$(ENV) ./bench --ecdsa handshake ECDHE-ECDSA-AES256-GCM-SHA384
	$(ENV) ./bench --ecdsa handshake TLS_AES_256_GCM_SHA384

measure-rsa: bench
	$(ENV) ./bench --rsa handshake TLS_AES_256_GCM_SHA384
	$(ENV) ./bench --rsa handshake ECDHE-RSA-AES256-GCM-SHA384

measure-ecdsa: bench
	$(ENV) ./bench --ecdsa handshake TLS_AES_256_GCM_SHA384
	$(ENV) ./bench --ecdsa handshake ECDHE-ECDSA-AES256-GCM-SHA384

memory: bench
	$(ENV) $(MEMUSAGE) ./bench memory ECDHE-RSA-AES256-GCM-SHA384 100
	$(ENV) $(MEMUSAGE) ./bench memory ECDHE-RSA-AES256-GCM-SHA384 1000
	$(ENV) $(MEMUSAGE) ./bench memory ECDHE-RSA-AES256-GCM-SHA384 5000
	$(ENV) $(MEMUSAGE) ./bench memory TLS_AES_256_GCM_SHA384 100
	$(ENV) $(MEMUSAGE) ./bench memory TLS_AES_256_GCM_SHA384 1000
	$(ENV) $(MEMUSAGE) ./bench memory TLS_AES_256_GCM_SHA384 5000

threads: bench
	for thr in $(shell ../rustls/admin/threads-seq.rs) ; do \
	  $(ENV) ./bench --threads $$thr handshake ECDHE-RSA-AES256-GCM-SHA384 ; \
	  $(ENV) ./bench --threads $$thr handshake-resume ECDHE-RSA-AES256-GCM-SHA384 ; \
	  $(ENV) ./bench --threads $$thr handshake-ticket ECDHE-RSA-AES256-GCM-SHA384 ; \
	  $(ENV) ./bench --threads $$thr handshake TLS_AES_256_GCM_SHA384 ; \
	  $(ENV) ./bench --threads $$thr handshake-ticket TLS_AES_256_GCM_SHA384 ; \
	  $(ENV) ./bench --threads $$thr bulk ECDHE-RSA-AES256-GCM-SHA384 1048576 ; \
	  $(ENV) ./bench --threads $$thr bulk TLS_AES_256_GCM_SHA384 1048576 ; \
	done

thread-latency: bench
	$(ENV) BENCH_LATENCY=latency-fullhs-tls12 ./bench --threads $$(nproc) handshake ECDHE-RSA-AES256-GCM-SHA384
	$(ENV) BENCH_LATENCY=latency-fullhs-tls13 ./bench --threads $$(nproc) handshake TLS_AES_256_GCM_SHA384
	$(ENV) BENCH_LATENCY=latency-resume-tls12 ./bench --threads $$(nproc) handshake-resume ECDHE-RSA-AES256-GCM-SHA384
	$(ENV) BENCH_LATENCY=latency-resume-tls13 ./bench --threads $$(nproc) handshake-ticket TLS_AES_256_GCM_SHA384
	cat latency-fullhs-tls12-server-*.tsv > latency-fullhs-tls12-server.tsv
	cat latency-fullhs-tls13-server-*.tsv > latency-fullhs-tls13-server.tsv
	cat latency-resume-tls12-server-*.tsv > latency-resume-tls12-server.tsv
	cat latency-resume-tls13-server-*.tsv > latency-resume-tls13-server.tsv

format: *.cc
	clang-format -i *.cc

clean:; rm -f bench *.o
