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

extra-boringssl: perf-aes256-boringssl.svg	\
	perf-chacha-boringssl.svg		\
	perf-fullhs-boringssl.svg		\
	perf-resume-boringssl.svg		\
	perf-ticket-boringssl.svg

extra-libressl: perf-aes256-libressl.svg	\
	perf-chacha-libressl.svg		\
	perf-fullhs-libressl.svg		\
	perf-resume-libressl.svg		\
	perf-ticket-libressl.svg

extra-openssl: perf-aes256-openssl.svg	\
	perf-chacha-openssl.svg		\
	perf-fullhs-openssl.svg		\
	perf-resume-openssl.svg		\
	perf-ticket-openssl.svg

extra-wolfssl: perf-aes256-wolfssl.svg	\
	perf-chacha-wolfssl.svg		\
	perf-fullhs-wolfssl.svg		\
	perf-resume-wolfssl.svg		\
	perf-ticket-wolfssl.svg

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

measure-rsa: measure-rsa-aws-lc	\
	measure-rsa-boringssl	\
	measure-rsa-libressl	\
	measure-rsa-openssl	\
	measure-rsa-wolfssl

measure-rsa-aws-lc: bench-aws-lc
	LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib ${ENV} \
			./$< --rsa handshake TLS_AES_256_GCM_SHA384
	LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib ${ENV} \
			./$< --rsa handshake ECDHE-RSA-AES256-GCM-SHA384

measure-rsa-boringssl: bench-boringssl
	LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< --rsa handshake TLS_AES_256_GCM_SHA384
	LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< --rsa handshake ECDHE-RSA-AES256-GCM-SHA384

measure-rsa-libressl: bench-libressl
	LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< --rsa handshake TLS_AES_256_GCM_SHA384
	LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< --rsa handshake ECDHE-RSA-AES256-GCM-SHA384

measure-rsa-openssl: bench-openssl
	LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< --rsa handshake TLS_AES_256_GCM_SHA384
	LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< --rsa handshake ECDHE-RSA-AES256-GCM-SHA384

measure-rsa-wolfssl: bench-wolfssl
	LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< --rsa handshake TLS_AES_256_GCM_SHA384
	LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< --rsa handshake ECDHE-RSA-AES256-GCM-SHA384

measure-ecdsa: measure-ecdsa-aws-lc	\
	measure-ecdsa-boringssl	\
	measure-ecdsa-libressl	\
	measure-ecdsa-openssl	\
	measure-ecdsa-wolfssl

measure-ecdsa-aws-lc: bench-aws-lc
	LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib ${ENV} \
			./$< --ecdsa handshake TLS_AES_256_GCM_SHA384
	LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib ${ENV} \
			./$< --ecdsa handshake ECDHE-ECDSA-AES256-GCM-SHA384

measure-ecdsa-boringssl: bench-boringssl
	LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< --ecdsa handshake TLS_AES_256_GCM_SHA384
	LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< --ecdsa handshake ECDHE-ECDSA-AES256-GCM-SHA384

measure-ecdsa-libressl: bench-libressl
	LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< --ecdsa handshake TLS_AES_256_GCM_SHA384
	LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< --ecdsa handshake ECDHE-ECDSA-AES256-GCM-SHA384

measure-ecdsa-openssl: bench-openssl
	LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< --ecdsa handshake TLS_AES_256_GCM_SHA384
	LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< --ecdsa handshake ECDHE-ECDSA-AES256-GCM-SHA384

measure-ecdsa-wolfssl: bench-wolfssl
	LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< --ecdsa handshake TLS_AES_256_GCM_SHA384
	LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} \
			./$< --ecdsa handshake ECDHE-ECDSA-AES256-GCM-SHA384

memory: memory-aws-lc		\
	memory-boringssl	\
	memory-libressl		\
	memory-openssl		\
	memory-wolfssl

memory-aws-lc: bench-aws-lc
	LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			./$< memory ECDHE-RSA-AES256-GCM-SHA384 100
	LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			./$< memory ECDHE-RSA-AES256-GCM-SHA384 1000
	LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			./$< memory ECDHE-RSA-AES256-GCM-SHA384 5000
	LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			./$< memory TLS_AES_256_GCM_SHA384 100
	LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			./$< memory TLS_AES_256_GCM_SHA384 1000
	LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			,/$< memory TLS_AES_256_GCM_SHA384 5000

memory-boringssl: bench-boringssl
	LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			./$< memory ECDHE-RSA-AES256-GCM-SHA384 100
	LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			./$< memory ECDHE-RSA-AES256-GCM-SHA384 1000
	LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			./$< memory ECDHE-RSA-AES256-GCM-SHA384 5000
	LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			./$< memory TLS_AES_256_GCM_SHA384 100
	LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			./$< memory TLS_AES_256_GCM_SHA384 1000
	LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			,/$< memory TLS_AES_256_GCM_SHA384 5000

memory-libressl: bench-libressl
	LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			./$< memory ECDHE-RSA-AES256-GCM-SHA384 100
	LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			./$< memory ECDHE-RSA-AES256-GCM-SHA384 1000
	LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			./$< memory ECDHE-RSA-AES256-GCM-SHA384 5000
	LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			./$< memory TLS_AES_256_GCM_SHA384 100
	LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			./$< memory TLS_AES_256_GCM_SHA384 1000
	LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			,/$< memory TLS_AES_256_GCM_SHA384 5000

memory-openssl: bench-openssl
	LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			./$< memory ECDHE-RSA-AES256-GCM-SHA384 100
	LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			./$< memory ECDHE-RSA-AES256-GCM-SHA384 1000
	LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			./$< memory ECDHE-RSA-AES256-GCM-SHA384 5000
	LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			./$< memory TLS_AES_256_GCM_SHA384 100
	LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			./$< memory TLS_AES_256_GCM_SHA384 1000
	LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			,/$< memory TLS_AES_256_GCM_SHA384 5000

memory-wolfssl: bench-wolfssl
	LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			./$< memory ECDHE-RSA-AES256-GCM-SHA384 100
	LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			./$< memory ECDHE-RSA-AES256-GCM-SHA384 1000
	LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			./$< memory ECDHE-RSA-AES256-GCM-SHA384 5000
	LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			./$< memory TLS_AES_256_GCM_SHA384 100
	LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			./$< memory TLS_AES_256_GCM_SHA384 1000
	LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} ${MEMUSAGE} \
			,/$< memory TLS_AES_256_GCM_SHA384 5000

threads: threads-aws-lc		\
	threads-boringssl	\
	threads-libressl	\
	threads-openssl		\
	threads-wolfssl

threads-aws-lc: bench-aws-lc
	for thr in $(shell ../rustls/admin/threads-seq.rs) ; do \
	  LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr handshake ECDHE-RSA-AES256-GCM-SHA384 ; \
	  LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr handshake ECDHE-RSA-AES256-GCM-SHA384 ; \
	  LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr handshake-resume ECDHE-RSA-AES256-GCM-SHA384 ; \
	  LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr handshake-ticket ECDHE-RSA-AES256-GCM-SHA384 ; \
	  LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr handshake TLS_AES_256_GCM_SHA384 ; \
	  LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr handshake-ticket TLS_AES_256_GCM_SHA384 ; \
	  LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr bulk ECDHE-RSA-AES256-GCM-SHA384 1048576 ; \
	  LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr bulk TLS_AES_256_GCM_SHA384 1048576 ; \
	done

threads-boringssl: bench-boringssl
	for thr in $(shell ../rustls/admin/threads-seq.rs) ; do \
	  LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr handshake ECDHE-RSA-AES256-GCM-SHA384 ; \
	  LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr handshake ECDHE-RSA-AES256-GCM-SHA384 ; \
	  LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr handshake-resume ECDHE-RSA-AES256-GCM-SHA384 ; \
	  LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr handshake-ticket ECDHE-RSA-AES256-GCM-SHA384 ; \
	  LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr handshake TLS_AES_256_GCM_SHA384 ; \
	  LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr handshake-ticket TLS_AES_256_GCM_SHA384 ; \
	  LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr bulk ECDHE-RSA-AES256-GCM-SHA384 1048576 ; \
	  LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr bulk TLS_AES_256_GCM_SHA384 1048576 ; \
	done

#
# note: handshake-resume is missing for libressl, libressl does
# not support session resumption
#
threads-libressl: bench-libressl
	for thr in $(shell ../rustls/admin/threads-seq.rs) ; do \
	  LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr handshake ECDHE-RSA-AES256-GCM-SHA384 ; \
	  LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr handshake ECDHE-RSA-AES256-GCM-SHA384 ; \
	  LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr handshake TLS_AES_256_GCM_SHA384 ; \
	  LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr bulk ECDHE-RSA-AES256-GCM-SHA384 1048576 ; \
	  LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr bulk TLS_AES_256_GCM_SHA384 1048576 ; \
	done

threads-openssl: bench-openssl
	for thr in $(shell ../rustls/admin/threads-seq.rs) ; do \
	  LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr handshake ECDHE-RSA-AES256-GCM-SHA384 ; \
	  LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr handshake ECDHE-RSA-AES256-GCM-SHA384 ; \
	  LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr handshake-resume ECDHE-RSA-AES256-GCM-SHA384 ; \
	  LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr handshake-ticket ECDHE-RSA-AES256-GCM-SHA384 ; \
	  LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr handshake TLS_AES_256_GCM_SHA384 ; \
	  LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr handshake-ticket TLS_AES_256_GCM_SHA384 ; \
	  LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr bulk ECDHE-RSA-AES256-GCM-SHA384 1048576 ; \
	  LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr bulk TLS_AES_256_GCM_SHA384 1048576 ; \
	done

threads-wolfssl: bench-wolfssl
	for thr in $(shell ../rustls/admin/threads-seq.rs) ; do \
	  LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr handshake ECDHE-RSA-AES256-GCM-SHA384 ; \
	  LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr handshake ECDHE-RSA-AES256-GCM-SHA384 ; \
	  LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr handshake-resume ECDHE-RSA-AES256-GCM-SHA384 ; \
	  LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} \
	    ./$< --threads $$thr handshake-ticket ECDHE-RSA-AES256-GCM-SHA384 ; \
	done
#
# currently becnc.cc trips assert at line 163:
#
#    if (!strcmp(ciphers, "TLS_AES_128_GCM_SHA256") ||
#        !strcmp(ciphers, "TLS_AES_256_GCM_SHA384") ||
#        !strcmp(ciphers, "TLS_CHACHA20_POLY1305_SHA256")) {
#      int err =
#          SSL_CTX_set1_groups_list(m_ctx, "X25519MLKEM768:X25519:P-256:P-384");
#      assert(err == 1);
#      set_version(TLS1_3_VERSION, TLS1_3_VERSION);
#ifndef WITH_BORINGSSL
#      SSL_CTX_set_ciphersuites(m_ctx, ciphers);
#
#	  LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} \
#	  	./$< --threads $$thr handshake TLS_AES_256_GCM_SHA384 ; \
#	  LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} \
#	  	./$< --threads $$thr handshake-ticket TLS_AES_256_GCM_SHA384 ; \
#	  LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} \
#	  	./$< --threads $$thr bulk ECDHE-RSA-AES256-GCM-SHA384 1048576 ; \
#	  LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV} \
#	  	./$< --threads $$thr bulk TLS_AES_256_GCM_SHA384 1048576 ; \
#

thread-latency: thread-latency-aws-lc	\
	thread-latency-boringssl	\
	thread-latency-libressl		\
	thread-latency-openssl		\
	thread-latency-wolfssl

thread-latency-aws-lc: latency-fullhs-tls12-server-aws-lc.tsv	\
	latency-fullhs-tls13-server-aws-lc.tsv			\
	latency-resume-tls12-server-aws-lc.tsv			\
	latency-resume-tls13-server-aws-lc.tsv

thread-latency-boringssl: latency-fullhs-tls12-server-boringssl.tsv	\
	latency-fullhs-tls13-server-boringssl.tsv			\
	latency-resume-tls12-server-boringssl.tsv			\
	latency-resume-tls13-server-boringssl.tsv

thread-latency-libressl: latency-fullhs-tls12-server-libressl.tsv	\
	latency-fullhs-tls13-server-libressl.tsv			\
	latency-resume-tls12-server-libressl.tsv			\
	latency-resume-tls13-server-libressl.tsv

thread-latency-openssl: latency-fullhs-tls12-server-openssl.tsv	\
	latency-fullhs-tls13-server-openssl.tsv			\
	latency-resume-tls12-server-openssl.tsv			\
	latency-resume-tls13-server-openssl.tsv

thread-latency-wolfssl: latency-fullhs-tls12-server-wolfssl.tsv	\
	latency-fullhs-tls13-server-wolfssl.tsv			\
	latency-resume-tls12-server-wolfssl.tsv			\
	latency-resume-tls13-server-wolfssl.tsv

latency-fullhs-tls12-server-aws-lc.tsv: bench-aws-lc
	rm -f latency-fullhs-tls12-*.tsv
	LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib ${ENV}	\
			BENCH_LATENCY=latency-fullhs-tls12	\
			./$< --threads $$(nproc) handshake ECDHE-RSA-AES256-GCM-SHA384
	cat latency-fullhs-tls12-server-*.tsv > $@

latency-fullhs-tls13-server-aws-lc.tsv: bench-aws-lc
	rm -f latency-fullhs-tls13-*.tsv
	LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib ${ENV}	\
			BENCH_LATENCY=latency-fullhs-tls13	\
			./$< --threads $$(nproc) handshake ECDHE-RSA-AES256-GCM-SHA384
	cat latency-fullhs-tls13-server-*.tsv > $@

latency-resume-tls12-server-aws-lc.tsv: bench-aws-lc
	rm -f latency-resume-tls12-*.tsv
	LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib ${ENV}	\
			BENCH_LATENCY=latency-resume-tls12	\
			./$< --threads $$(nproc) handshake-resume ECDHE-RSA-AES256-GCM-SHA384
	cat latency-resume-tls12-server-*.tsv > $@

latency-resume-tls13-server-aws-lc.tsv: bench-aws-lc
	rm -f latency-resume-tls13-*.tsv
	LD_LIBRARY_PATH=${AWS_INSTALL_PREFIX}/lib ${ENV}	\
			BENCH_LATENCY=latency-resume-tls13	\
			./$< --threads $$(nproc) handshake-ticket TLS_AES_256_GCM_SHA384
	cat latency-resume-tls13-server-*.tsv > $@

latency-fullhs-tls12-server-boringssl.tsv: bench-boringssl
	rm -f latency-fullhs-tls12-*.tsv
	LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV}	\
			BENCH_LATENCY=latency-fullhs-tls12	\
			./$< --threads $$(nproc) handshake ECDHE-RSA-AES256-GCM-SHA384
	cat latency-fullhs-tls12-server-*.tsv > $@

latency-fullhs-tls13-server-boringssl.tsv: bench-boringssl
	rm -f latency-fullhs-tls13-*.tsv
	LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV}	\
			BENCH_LATENCY=latency-fullhs-tls13	\
			./$< --threads $$(nproc) handshake ECDHE-RSA-AES256-GCM-SHA384
	cat latency-fullhs-tls13-server-*.tsv > $@

latency-resume-tls12-server-boringssl.tsv: bench-boringssl
	rm -f latency-resume-tls12-*.tsv
	LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV}	\
			BENCH_LATENCY=latency-resume-tls12	\
			./$< --threads $$(nproc) handshake-resume ECDHE-RSA-AES256-GCM-SHA384
	cat latency-resume-tls12-server-*.tsv > $@

latency-resume-tls13-server-boringssl.tsv: bench-boringssl
	rm -f latency-resume-tls13-*.tsv
	LD_LIBRARY_PATH=${BORINGSSL_INSTALL_PREFIX}/lib ${ENV}	\
			BENCH_LATENCY=latency-resume-tls13	\
			./$< --threads $$(nproc) handshake-ticket TLS_AES_256_GCM_SHA384
	cat latency-resume-tls13-server-*.tsv > $@

latency-fullhs-tls12-server-libressl.tsv: bench-libressl
	rm -f latency-fullhs-tls12-*.tsv
	LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV}	\
			BENCH_LATENCY=latency-fullhs-tls12	\
			./$< --threads $$(nproc) handshake ECDHE-RSA-AES256-GCM-SHA384
	cat latency-fullhs-tls12-server-*.tsv > $@

latency-fullhs-tls13-server-libressl.tsv: bench-libressl
	rm -f latency-fullhs-tls13-*.tsv
	LD_LIBRARY_PATH=${LIBRESSL_INSTALL_PREFIX}/lib ${ENV}	\
			BENCH_LATENCY=latency-fullhs-tls13	\
			./$< --threads $$(nproc) handshake ECDHE-RSA-AES256-GCM-SHA384
	cat latency-fullhs-tls13-server-*.tsv > $@

latency-resume-tls12-server-libressl.tsv: bench-libressl
	touch $@

latency-resume-tls13-server-libressl.tsv: bench-libressl
	touch $@

latency-fullhs-tls12-server-openssl.tsv: bench-openssl
	rm -f latency-fullhs-tls12-server-*.tsv
	LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV}	\
			BENCH_LATENCY=latency-fullhs-tls12	\
			./$< --threads $$(nproc) handshake ECDHE-RSA-AES256-GCM-SHA384
	cat latency-fullhs-tls12-server-*.tsv > $@

latency-fullhs-tls13-server-openssl.tsv: bench-openssl
	rm -f latency-fullhs-tls13-server-*.tsv
	LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV}	\
			BENCH_LATENCY=latency-fullhs-tls13	\
			./$< --threads $$(nproc) handshake ECDHE-RSA-AES256-GCM-SHA384
	cat latency-fullhs-tls13-server-*.tsv > $@

latency-resume-tls12-server-openssl.tsv: bench-openssl
	rm -f latency-resume-tls12-server-*.tsv
	LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV}	\
			BENCH_LATENCY=latency-resume-tls12	\
			./$< --threads $$(nproc) handshake-resume ECDHE-RSA-AES256-GCM-SHA384
	cat latency-resume-tls12-server-*.tsv > $@

latency-resume-tls13-server-openssl.tsv: bench-openssl
	rm -f latency-resume-tls13-server-*.tsv
	LD_LIBRARY_PATH=${OPENSSL_INSTALL_PREFIX}/lib ${ENV}	\
			BENCH_LATENCY=latency-resume-tls13	\
			./$< --threads $$(nproc) handshake-ticket TLS_AES_256_GCM_SHA384
	cat latency-resume-tls13-server-*.tsv > $@

latency-fullhs-tls12-server-wolfssl.tsv: bench-wolfssl
	rm -f latency-fullhs-tls12-server-*.tsv
	LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV}	\
			BENCH_LATENCY=latency-fullhs-tls12	\
			./$< --threads $$(nproc) handshake ECDHE-RSA-AES256-GCM-SHA384
	cat latency-fullhs-tls12-server-*.tsv > $@

latency-fullhs-tls13-server-wolfssl.tsv: bench-wolfssl
	rm -f latency-fullhs-tls13-server-*.tsv
	LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV}	\
			BENCH_LATENCY=latency-fullhs-tls13	\
			./$< --threads $$(nproc) handshake ECDHE-RSA-AES256-GCM-SHA384
	cat latency-fullhs-tls13-server-*.tsv > $@

latency-resume-tls12-server-wolfssl.tsv: bench-wolfssl
	rm -f latency-resume-tls12-server-*.tsv
	LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV}	\
			BENCH_LATENCY=latency-resume-tls12	\
			./$< --threads $$(nproc) handshake-resume ECDHE-RSA-AES256-GCM-SHA384
	cat latency-resume-tls12-server-*.tsv > $@

#
# currently becnc.cc trips assert at line 163:
#
#    if (!strcmp(ciphers, "TLS_AES_128_GCM_SHA256") ||
#        !strcmp(ciphers, "TLS_AES_256_GCM_SHA384") ||
#        !strcmp(ciphers, "TLS_CHACHA20_POLY1305_SHA256")) {
#      int err =
#          SSL_CTX_set1_groups_list(m_ctx, "X25519MLKEM768:X25519:P-256:P-384");
#      assert(err == 1);
#      set_version(TLS1_3_VERSION, TLS1_3_VERSION);
#ifndef WITH_BORINGSSL
#      SSL_CTX_set_ciphersuites(m_ctx, ciphers);
#else
latency-resume-tls13-server-wolfssl.tsv: bench-wolfssl
	touch $@
#	rm -f latency-resume-tls13-server-*.tsv
#	LD_LIBRARY_PATH=${WOLFSSL_INSTALL_PREFIX}/lib ${ENV}	\
#			BENCH_LATENCY=latency-resume-tls13	\
#			./$< --threads $$(nproc) handshake-ticket TLS_AES_256_GCM_SHA384
#	cat latency-resume-tls13-server-*.tsv > $@

format: *.cc
	clang-format -i *.cc

clean:;
	rm -f bench bench-aws-lc bench-boringssl \
		bench-libressl bench-openssl bench-wolfssl *.o *.svg
