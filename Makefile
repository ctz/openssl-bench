CXXFLAGS+=-g -Wall -Werror -O3

ifeq (,$(BORINGSSL))
  CPPFLAGS+=-I../openssl/include
  LDFLAGS+=-L../openssl
  ENV=env LD_LIBRARY_PATH=../openssl
else
  CC=clang
  CXX=clang++
  CPPFLAGS+=-I../boringssl/include -DBORINGSSL=1
  LDFLAGS+=-L../boringssl
  ENV=env LD_LIBRARY_PATH=../boringssl
endif
LDLIBS+=-lssl -lcrypto -ldl -lpthread
MEMUSAGE=/usr/bin/time -f %M

bench: bench.cc
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

format: *.cc
	clang-format -i *.cc

clean:; rm -f bench *.o
