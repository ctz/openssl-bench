#CXXFLAGS+=-g -Wall -Werror -O3 -std=c++17
CXXFLAGS+=-g -Wall -Werror -O0 -std=c++17

LDLIBS+=-ldl -lpthread
MEMUSAGE=/usr/bin/time -f %M

AWSLC_LDFLAGS=-L$(AWS_INSTALL_PREFIX)/lib
AWSLC_LDLIBS=$(LDLIBS) -lssl -lcrypto
AWSLC_CXXFLAGS=$(CXXFLAGS) -DWITH_AWS -I$(AWS_INSTALL_PREFIX)/include
bench-aws-lc: bench.cc
	$(CXX) $(AWSLC_CXXFLAGS) $< -o $@ $(AWSLC_LDFLAGS) $(AWSLC_LDLIBS)

BORINGSSL_LDFLAGS=-L$(BORINGSSL_INSTALL_PREFIX)/lib
BORINGSSL_LDLIBS=$(LDLIBS) -lssl -lcrypto
BORINGSSL_CXXFLAGS=$(CXXFLAGS) -DWITH_BORINGSSL -I$(BORINGSSL_INSTALL_PREFIX)/include
bench-boringssl: bench.cc
	$(CXX) $(BORINGSSL_CXXFLAGS) $< -o $@ $(BORINGSSL_LDFLAGS) $(BORINGSSL_LDLIBS)

LIBRESSL_LDFLAGS=-L$(LIBRESSL_INSTALL_PREFIX)/lib
LIBRESSL_LDLIBS=$(LDLIBS) -lssl -lcrypto
LIBRESSL_CXXFLAGS=$(CXXFLAGS) -DWITH_LIBRESSL -I$(LIBRESSL_INSTALL_PREFIX)/include
bench-libressl: bench.cc
	$(CXX) $(LIBRESSL_CXXFLAGS) $< -o $@ $(LIBRESSL_LDFLAGS) $(LIBRESSL_LDLIBS)

OPENSSL_LDFLAGS=-L$(OPENSSL_INSTALL_PREFIX)/lib
OPENSSL_LDLIBS=$(LDLIBS) -lssl -lcrypto
OPENSSL_CXXFLAGS=$(CXXFLAGS) -DWITH_OPENSSL -I$(OPENSSL_INSTALL_PREFIX)/include
bench-openssl: bench.cc
	$(CXX) $(OPENSSL_CXXFLAGS) $< -o $@ $(OPENSSL_LDFLAGS) $(OPENSSL_LDLIBS)

WOLFSSL_LDFLAGS=-L$(WOLFSSL_INSTALL_PREFIX)/lib
WOLFSSL_LDLIBS=$(LDLIBS) -lwolfssl
WOLFSSL_CXXFLAGS=$(CXXFLAGS) -DWITH_WOLFSSL -I$(WOLFSSL_INSTALL_PREFIX)/include/wolfssl
WOLFSSL_CXXFLAGS+=-I$(WOLFSSL_INSTALL_PREFIX)/include/
bench-wolfssl: bench.cc
	$(CXX) $(WOLFSSL_CXXFLAGS) $< -o $@ $(WOLFSSL_LDFLAGS) $(WOLFSSL_LDLIBS)


perf-aes128-handshake-aws-lc.svg: bench-aws-lc
	LD_LIBRARY_PATH=$(AWS_INSTALL_PREFIX)/lib $(ENV) perf record \
			-F9999 --call-graph dwarf -- ./$< handshake ECDHE-RSA-AES128-GCM-SHA256 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-aes128-resume-aws-lc.svg: bench-aws-lc
	LD_LIBRARY_PATH=$(AWS_INSTALL_PREFIX)/lib $(ENV) perf record \
			-F9999 --call-graph dwarf -- ./$< handshake-resume ECDHE-RSA-AES128-GCM-SHA256 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-aes128-ticket-aws-lc.svg: bench-aws-lc
	LD_LIBRARY_PATH=$(AWS_INSTALL_PREFIX)/lib $(ENV) perf record \
			-F9999 --call-graph dwarf -- ./$< handshake-ticket ECDHE-RSA-AES128-GCM-SHA256 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-aes128-handshake-boringssl.svg: bench-boringssl
	LD_LIBRARY_PATH=$(BORINGSSL_INSTALL_PREFIX)/lib $(ENV) perf record \
			 -F9999 --call-graph dwarf -- ./$< handshake ECDHE-RSA-AES128-GCM-SHA256 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-aes128-resume-boringssl.svg: bench-boringssl
	LD_LIBRARY_PATH=$(BORINGSSL_INSTALL_PREFIX)/lib $(ENV) perf record \
			-F9999 --call-graph dwarf -- ./$< handshake-resume ECDHE-RSA-AES128-GCM-SHA256 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-aes128-ticket-boringssl.svg: bench-boringssl
	LD_LIBRARY_PATH=$(BORINGSSL_INSTALL_PREFIX)/lib $(ENV) perf record \
			-F9999 --call-graph dwarf -- ./$< handshake-ticket ECDHE-RSA-AES128-GCM-SHA256 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-aes128-handshake-libressl.svg: bench-libressl
	LD_LIBRARY_PATH=$(LIBRESSL_INSTALL_PREFIX)/lib $(ENV) perf record \
			-F9999 --call-graph dwarf -- ./$< handshake ECDHE-RSA-AES128-GCM-SHA256 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-aes128-resume-libressl.svg: bench-libressl
	echo "libressl does not support session resumption" > $@
	#LD_LIBRARY_PATH=$(LIBRESSL_INSTALL_PREFIX)/lib $(ENV) perf record \
	#		-F9999 --call-graph dwarf -- ./$< handshake-resume ECDHE-RSA-AES128-GCM-SHA256 1048576
	#perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-aes128-ticket-libressl.svg: bench-libressl
	echo "libressl does not support session resumption" > $@
	#LD_LIBRARY_PATH=$(LIBRESSL_INSTALL_PREFIX)/lib $(ENV) perf record \
	#		-F9999 --call-graph dwarf -- ./$< handshake-ticket ECDHE-RSA-AES128-GCM-SHA256 1048576
	#perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-aes128-handshake-openssl.svg: bench-openssl
	LD_LIBRARY_PATH=$(OPENSSL_INSTALL_PREFIX)/lib $(ENV) perf record \
			-F9999 --call-graph dwarf -- ./$< handshake ECDHE-RSA-AES128-GCM-SHA256 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-aes128-resume-openssl.svg: bench-openssl
	LD_LIBRARY_PATH=$(OPENSSL_INSTALL_PREFIX)/lib $(ENV) perf record \
			-F9999 --call-graph dwarf -- ./$< handshake-resume ECDHE-RSA-AES128-GCM-SHA256 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-aes128-ticket-openssl.svg: bench-openssl
	LD_LIBRARY_PATH=$(OPENSSL_INSTALL_PREFIX)/lib $(ENV) perf record \
			-F9999 --call-graph dwarf -- ./$< handshake-ticket ECDHE-RSA-AES128-GCM-SHA256 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-aes128-handshake-wolfssl.svg: bench-wolfssl
	LD_LIBRARY_PATH=$(WOLFSSL_INSTALL_PREFIX)/lib $(ENV) perf record \
			-F9999 --call-graph dwarf -- ./$< handshake ECDHE-RSA-AES128-GCM-SHA256 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-aes128-resume-wolfssl.svg: bench-wolfssl
	LD_LIBRARY_PATH=$(WOLFSSL_INSTALL_PREFIX)/lib $(ENV) perf record \
			-F9999 --call-graph dwarf -- ./$< handshake-resume ECDHE-RSA-AES128-GCM-SHA256 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-aes128-ticket-wolfssl.svg: bench-wolfssl
	LD_LIBRARY_PATH=$(WOLFSSL_INSTALL_PREFIX)/lib $(ENV) perf record \
			-F9999 --call-graph dwarf -- ./$< handshake-ticket ECDHE-RSA-AES128-GCM-SHA256 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf.data: perf-aes128-handshake-aws-lc.svg	\
	perf-aes128-resume-aws-lc.svg		\
	perf-aes128-ticket-aws-lc.svg		\
	perf-aes128-handshake-boringssl.svg	\
	perf-aes128-resume-boringssl.svg	\
	perf-aes128-ticket-boringssl.svg	\
	perf-aes128-handshake-libressl.svg	\
	perf-aes128-resume-libressl.svg		\
	perf-aes128-ticket-libressl.svg		\
	perf-aes128-handshake-openssl.svg	\
	perf-aes128-resume-openssl.svg		\
	perf-aes128-ticket-openssl.svg		\
	perf-aes128-handshake-wolfssl.svg	\
	perf-aes128-resume-wolfssl.svg	\
	perf-aes128-ticket-wolfssl.svg

extra:	extra-aws-lc	\
	extra-boringssl	\
	extra-libressl	\
	extra-openssl	\
	extra-wolfssl

extra-aws-lc:  perf-aes256-aws-lc.svg	\
	perf-chacha-aws-lc.svg		\
	perf-fullhs-aws-lc.svg		\
	perf-resume-aws-lc.svg		\
	perf-ticket-aws-lc.svg

##
## aws-lc perf charts
##
perf-aes256-aws-lc.svg: bench-aws-lc
	LD_LIBRARY_PATH=$(AWS_INSTALL_PREFIX)/lib \
			perf record -F9999 --call-graph dwarf -- \
			$(ENV) ./$< bulk ECDHE-RSA-AES256-GCM-SHA384 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-chacha-aws-lc.svg: bench-aws-lc
	LD_LIBRARY_PATH=$(AWS_INSTALL_PREFIX)/lib \
			perf record -F9999 --call-graph dwarf -- \
			$(ENV) ./$< bulk ECDHE-RSA-CHACHA20-POLY1305 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-fullhs-aws-lc.svg: bench-aws-lc
	LD_LIBRARY_PATH=$(AWS_INSTALL_PREFIX)/lib \
			perf record -F9999 --call-graph dwarf -- \
			$(ENV) ./$< handshake ECDHE-RSA-AES256-GCM-SHA384
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-resume-aws-lc.svg: bench-aws-lc
	LD_LIBRARY_PATH=$(AWS_INSTALL_PREFIX)/lib \
			perf record -F9999 --call-graph dwarf -- \
			$(ENV) ./$< handshake ECDHE-RSA-AES256-GCM-SHA384
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-ticket-aws-lc.svg: bench-aws-lc
	LD_LIBRARY_PATH=$(AWS_INSTALL_PREFIX)/lib \
			perf record -F9999 --call-graph dwarf -- \
			$(ENV) ./$< handshake-ticket ECDHE-RSA-AES256-GCM-SHA384
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

##
## boringssl perf charts
##
perf-aes256-boringssl.svg: bench-boringssl
	LD_LIBRARY_PATH=$(BORINGSSL_INSTALL_PREFIX)/lib \
			perf record -F9999 --call-graph dwarf -- \
			$(ENV) ./$< bulk ECDHE-RSA-AES256-GCM-SHA384 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-chacha-boringssl.svg: bench-boringssl
	LD_LIBRARY_PATH=$(BORINGSSL_INSTALL_PREFIX)/lib \
			perf record -F9999 --call-graph dwarf -- \
			$(ENV) ./$< bulk ECDHE-RSA-CHACHA20-POLY1305 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-fullhs-boringssl.svg: bench-boringssl
	LD_LIBRARY_PATH=$(BORINGSSL_INSTALL_PREFIX)/lib \
			perf record -F9999 --call-graph dwarf -- \
			$(ENV) ./$< handshake ECDHE-RSA-AES256-GCM-SHA384
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-resume-boringssl.svg: bench-boringssl
	LD_LIBRARY_PATH=$(BORINGSSL_INSTALL_PREFIX)/lib \
			perf record -F9999 --call-graph dwarf -- \
			$(ENV) ./$< handshake ECDHE-RSA-AES256-GCM-SHA384
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-ticket-boringssl.svg: bench-boringssl
	LD_LIBRARY_PATH=$(BORINGSSL_INSTALL_PREFIX)/lib \
			perf record -F9999 --call-graph dwarf -- \
			$(ENV) ./$< handshake-ticket ECDHE-RSA-AES256-GCM-SHA384
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

##
## libressl perf charts
##
perf-aes256-libressl.svg: bench-libressl
	LD_LIBRARY_PATH=$(LIBRESSL_INSTALL_PREFIX)/lib \
			perf record -F9999 --call-graph dwarf -- \
			$(ENV) ./$< bulk ECDHE-RSA-AES256-GCM-SHA384 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-chacha-libressl.svg: bench-libressl
	LD_LIBRARY_PATH=$(LIBRESSL_INSTALL_PREFIX)/lib \
			perf record -F9999 --call-graph dwarf -- \
			$(ENV) ./$< bulk ECDHE-RSA-CHACHA20-POLY1305 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-fullhs-libressl.svg: bench-libressl
	LD_LIBRARY_PATH=$(LIBRESSL_INSTALL_PREFIX)/lib \
			perf record -F9999 --call-graph dwarf -- \
			$(ENV) ./$< handshake ECDHE-RSA-AES256-GCM-SHA384
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-resume-libressl.svg: bench-libressl
	LD_LIBRARY_PATH=$(LIBRESSL_INSTALL_PREFIX)/lib \
			perf record -F9999 --call-graph dwarf -- \
			$(ENV) ./$< handshake ECDHE-RSA-AES256-GCM-SHA384
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-ticket-libressl.svg: bench-libressl
	LD_LIBRARY_PATH=$(LIBRESSL_INSTALL_PREFIX)/lib \
			perf record -F9999 --call-graph dwarf -- \
			$(ENV) ./$< handshake-ticket ECDHE-RSA-AES256-GCM-SHA384
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

##
## openssl perf charts
##
perf-aes256-openssl.svg: bench-openssl
	LD_LIBRARY_PATH=$(OPENSSL_INSTALL_PREFIX)/lib \
			perf record -F9999 --call-graph dwarf -- \
			$(ENV) ./$< bulk ECDHE-RSA-AES256-GCM-SHA384 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-chacha-openssl.svg: bench-openssl
	LD_LIBRARY_PATH=$(OPENSSL_INSTALL_PREFIX)/lib \
			perf record -F9999 --call-graph dwarf -- \
			$(ENV) ./$< bulk ECDHE-RSA-CHACHA20-POLY1305 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-fullhs-openssl.svg: bench-openssl
	LD_LIBRARY_PATH=$(OPENSSL_INSTALL_PREFIX)/lib \
			perf record -F9999 --call-graph dwarf -- \
			$(ENV) ./$< handshake ECDHE-RSA-AES256-GCM-SHA384
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-resume-openssl.svg: bench-openssl
	LD_LIBRARY_PATH=$(OPENSSL_INSTALL_PREFIX)/lib \
			perf record -F9999 --call-graph dwarf -- \
			$(ENV) ./$< handshake ECDHE-RSA-AES256-GCM-SHA384
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-ticket-openssl.svg: bench-openssl
	LD_LIBRARY_PATH=$(OPENSSL_INSTALL_PREFIX)/lib \
			perf record -F9999 --call-graph dwarf -- \
			$(ENV) ./$< handshake-ticket ECDHE-RSA-AES256-GCM-SHA384
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

##
## wolfssl perf charts
##
perf-aes256-wolfssl.svg: bench-wolfssl
	LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib \
			perf record -F9999 --call-graph dwarf -- \
			$(ENV) ./$< bulk ECDHE-RSA-AES256-GCM-SHA384 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-chacha-wolfssl.svg: bench-wolfssl
	LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib \
			perf record -F9999 --call-graph dwarf -- \
			$(ENV) ./$< bulk ECDHE-RSA-CHACHA20-POLY1305 1048576
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-fullhs-wolfssl.svg: bench-wolfssl
	LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib \
			perf record -F9999 --call-graph dwarf -- \
			$(ENV) ./$< handshake ECDHE-RSA-AES256-GCM-SHA384
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-resume-wolfssl.svg: bench-wolfssl
	LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib \
			perf record -F9999 --call-graph dwarf -- \
			$(ENV) ./$< handshake ECDHE-RSA-AES256-GCM-SHA384
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

perf-ticket-wolfssl.svg: bench-wolfssl
	LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib \
			perf record -F9999 --call-graph dwarf -- \
			$(ENV) ./$< handshake-ticket ECDHE-RSA-AES256-GCM-SHA384
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > $@

measure: measure-aws-lc	\
	measure-boringssl \
	measure-libressl \
	measure-openssl \
	measure-wolfssl

measure-aws-lc: bench-aws-lc
	LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib $(ENV) \
			./$< bulk ECDHE-RSA-AES128-GCM-SHA256 1048576
	LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib $(ENV) \
			./$< bulk ECDHE-RSA-AES256-GCM-SHA384 1048576
	LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib $(ENV) \
			./$< bulk ECDHE-RSA-CHACHA20-POLY1305 1048576
	LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib $(ENV) \
			./$< bulk TLS_AES_256_GCM_SHA384 1048576
	LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib $(ENV) \
			./$< handshake ECDHE-RSA-AES256-GCM-SHA384
	LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib $(ENV) \
			./$< handshake-resume ECDHE-RSA-AES256-GCM-SHA384
	LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib $(ENV) \
			./$< handshake-ticket ECDHE-RSA-AES256-GCM-SHA384
	LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib $(ENV) \
			./$< handshake TLS_AES_256_GCM_SHA384
	#LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib $(ENV) \
			./bench handshake-resume TLS_AES_256_GCM_SHA384
	LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib $(ENV) \
			./$< handshake-ticket TLS_AES_256_GCM_SHA384
	LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib $(ENV) \
			./$< --ecdsa handshake ECDHE-ECDSA-AES256-GCM-SHA384
	LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib $(ENV) \
			./$< --ecdsa handshake TLS_AES_256_GCM_SHA384

measure-boringssl: bench-boringssl
	LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< bulk ECDHE-RSA-AES128-GCM-SHA256 1048576
	LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< bulk ECDHE-RSA-AES256-GCM-SHA384 1048576
	LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< bulk ECDHE-RSA-CHACHA20-POLY1305 1048576
	LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< bulk TLS_AES_256_GCM_SHA384 1048576
	LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< handshake ECDHE-RSA-AES256-GCM-SHA384
	LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< handshake-resume ECDHE-RSA-AES256-GCM-SHA384
	LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< handshake-ticket ECDHE-RSA-AES256-GCM-SHA384
	LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< handshake TLS_AES_256_GCM_SHA384
	LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< handshake-resume TLS_AES_256_GCM_SHA384
	LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< handshake-ticket TLS_AES_256_GCM_SHA384
	LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< --ecdsa handshake ECDHE-ECDSA-AES256-GCM-SHA384
	LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< --ecdsa handshake TLS_AES_256_GCM_SHA384

measure-libressl: bench-libressl
	LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< bulk ECDHE-RSA-AES128-GCM-SHA256 1048576
	LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< bulk ECDHE-RSA-AES256-GCM-SHA384 1048576
	LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< bulk ECDHE-RSA-CHACHA20-POLY1305 1048576
	LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< bulk TLS_AES_256_GCM_SHA384 1048576
	LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< handshake ECDHE-RSA-AES256-GCM-SHA384
	LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< handshake-resume ECDHE-RSA-AES256-GCM-SHA384
	LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< handshake-ticket ECDHE-RSA-AES256-GCM-SHA384
	LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< handshake TLS_AES_256_GCM_SHA384
	LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< handshake-resume TLS_AES_256_GCM_SHA384
	LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< handshake-ticket TLS_AES_256_GCM_SHA384
	LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< --ecdsa handshake ECDHE-ECDSA-AES256-GCM-SHA384
	LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< --ecdsa handshake TLS_AES_256_GCM_SHA384

measure-openssl: bench-openssl
	LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< bulk ECDHE-RSA-AES128-GCM-SHA256 1048576
	LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< bulk ECDHE-RSA-AES256-GCM-SHA384 1048576
	LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< bulk ECDHE-RSA-CHACHA20-POLY1305 1048576
	LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< bulk TLS_AES_256_GCM_SHA384 1048576
	LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< handshake ECDHE-RSA-AES256-GCM-SHA384
	LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< handshake-resume ECDHE-RSA-AES256-GCM-SHA384
	LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< handshake-ticket ECDHE-RSA-AES256-GCM-SHA384
	LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< handshake TLS_AES_256_GCM_SHA384
	LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< handshake-resume TLS_AES_256_GCM_SHA384
	LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< handshake-ticket TLS_AES_256_GCM_SHA384
	LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< --ecdsa handshake ECDHE-ECDSA-AES256-GCM-SHA384
	LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< --ecdsa handshake TLS_AES_256_GCM_SHA384

measure-wolfssl: bench-wolfssl
	LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< bulk ECDHE-RSA-AES128-GCM-SHA256 1048576
	LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< bulk ECDHE-RSA-AES256-GCM-SHA384 1048576
	LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< bulk ECDHE-RSA-CHACHA20-POLY1305 1048576
	LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< bulk TLS_AES_256_GCM_SHA384 1048576
	LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< handshake ECDHE-RSA-AES256-GCM-SHA384
	LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< handshake-resume ECDHE-RSA-AES256-GCM-SHA384
	LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< handshake-ticket ECDHE-RSA-AES256-GCM-SHA384
	#LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} \
	#		./$< handshake TLS_AES_256_GCM_SHA384
	#LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} \
	#		./$< handshake-resume TLS_AES_256_GCM_SHA384
	#LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} \
	#		./$< handshake-ticket TLS_AES_256_GCM_SHA384
	#LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} \
	#		./$< --ecdsa handshake ECDHE-ECDSA-AES256-GCM-SHA384
	#LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} \
	#		./$< --ecdsa handshake TLS_AES_256_GCM_SHA384

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

clean:;
	rm -f bench bench-aws-lc bench-boringssl \
		bench-libressl bench-openssl bench-wolfssl *.o *.svg
