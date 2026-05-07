#!/usr/bin/env bash
set -euo pipefail

PREFIX="${PREFIX:-/opt/modsecurity}"
MODSEC_VERSION="${MODSEC_VERSION:-v3.0.15}"
PCRE2_VERSION="${PCRE2_VERSION:-pcre2-10.44}"
CURL_VERSION="${CURL_VERSION:-curl-8_11_0}"
WORKDIR="${WORKDIR:-$(pwd)/vendor}"
JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)}"

mkdir -p "$WORKDIR" "$PREFIX"
cd "$WORKDIR"

# Build a minimal libcurl: HTTP/HTTPS only, OpenSSL TLS, zlib. We avoid the
# default RHEL/AlmaLinux libcurl because its krb5/ldap/ssh/libpsl/libidn2/
# nghttp2/brotli deps balloon the wheel and pull libselinux (which links
# libpcre2 — defeating our static-pcre2 work).
if [ ! -f "$PREFIX/lib/libcurl.so" ] && [ ! -f "$PREFIX/lib64/libcurl.so" ] \
   && [ ! -f "$PREFIX/lib/libcurl.dylib" ] && [ ! -f "$PREFIX/lib64/libcurl.dylib" ]; then
    echo "==> Building minimal libcurl from source"
    if [ ! -d curl ]; then
        git clone --depth 1 --branch "$CURL_VERSION" https://github.com/curl/curl.git
    fi
    CURL_TLS_FLAG="--with-openssl"
    if [ "$(uname -s)" = "Darwin" ] && command -v brew >/dev/null 2>&1; then
        _ossl="$(brew --prefix openssl@3 2>/dev/null || true)"
        [ -n "$_ossl" ] && CURL_TLS_FLAG="--with-openssl=$_ossl"
    fi
    (cd curl && autoreconf -fi && ./configure \
        --prefix="$PREFIX" \
        $CURL_TLS_FLAG \
        --with-zlib \
        --enable-shared --disable-static \
        --disable-ldap --disable-ldaps \
        --disable-rtsp --disable-dict --disable-telnet --disable-tftp \
        --disable-pop3 --disable-imap --disable-smtp \
        --disable-gopher --disable-mqtt --disable-smb \
        --disable-manual --disable-docs \
        --without-gssapi \
        --without-libssh --without-libssh2 \
        --without-libpsl --without-libidn2 \
        --without-nghttp2 --without-ngtcp2 --without-nghttp3 \
        --without-brotli --without-zstd \
        --without-libgsasl \
        --with-ca-fallback \
        && make -j"$JOBS" && make install)
fi

# Build pcre2 as a static lib so it gets baked into libmodsecurity.so
if [ ! -f "$PREFIX/lib/libpcre2-8.a" ] && [ ! -f "$PREFIX/lib64/libpcre2-8.a" ]; then
    echo "==> Building pcre2 (static) from source"
    if [ ! -d pcre2 ]; then
        git clone --depth 1 --branch "$PCRE2_VERSION" \
            https://github.com/PCRE2Project/pcre2.git
    fi
    cmake -S pcre2 -B pcre2/build \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DBUILD_SHARED_LIBS=OFF \
        -DPCRE2_BUILD_PCRE2_8=ON \
        -DPCRE2_BUILD_TESTS=OFF \
        -DPCRE2_BUILD_PCRE2GREP=OFF
    cmake --build pcre2/build -j"$JOBS"
    cmake --install pcre2/build
fi

# Build yajl as a static lib (BUILD_SHARED_LIBS=OFF + belt-and-suspenders rm
# of any shared output, since yajl's old CMake doesn't fully respect the flag).
if [ ! -f "$PREFIX/lib/libyajl_s.a" ] && [ ! -f "$PREFIX/lib64/libyajl_s.a" ] \
   && [ ! -f "$PREFIX/lib/libyajl.a" ] && [ ! -f "$PREFIX/lib64/libyajl.a" ]; then
    echo "==> Building yajl (static) from source"
    if [ ! -d yajl ]; then
        git clone --depth 1 --branch 2.1.0 https://github.com/lloyd/yajl.git
    fi
    # yajl 2.1.0's reformatter/verify/example subdirs use CMake patterns
    # (EXEC_PROGRAM, target LOCATION) that are hard errors in CMake 3.27+.
    # We only need libyajl_s.a from src/, so drop the rest.
    sed -i.bak -E '/^ADD_SUBDIRECTORY[[:space:]]*\((reformatter|verify|example|perf|test)\)/d' \
        yajl/CMakeLists.txt
    cmake -S yajl -B yajl/build \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DBUILD_SHARED_LIBS=OFF \
        -DCMAKE_POLICY_VERSION_MINIMUM=3.5
    cmake --build yajl/build -j"$JOBS"
    cmake --install yajl/build
fi

# Make sure no shared variant survives so the linker picks the .a.
rm -f "$PREFIX"/lib/libpcre2-8.so* "$PREFIX"/lib64/libpcre2-8.so* \
      "$PREFIX"/lib/libpcre2-8.*dylib "$PREFIX"/lib64/libpcre2-8.*dylib \
      "$PREFIX"/lib/libyajl.so* "$PREFIX"/lib64/libyajl.so* \
      "$PREFIX"/lib/libyajl.*dylib "$PREFIX"/lib64/libyajl.*dylib 2>/dev/null || true

export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig:$PREFIX/lib64/pkgconfig:${PKG_CONFIG_PATH:-}"
export LD_LIBRARY_PATH="$PREFIX/lib:$PREFIX/lib64:${LD_LIBRARY_PATH:-}"

if [ ! -d ModSecurity-src ]; then
    echo "==> Cloning ModSecurity $MODSEC_VERSION"
    git clone --depth 1 --branch "$MODSEC_VERSION" \
        --recurse-submodules --shallow-submodules \
        https://github.com/owasp-modsecurity/ModSecurity.git ModSecurity-src
fi

cd ModSecurity-src

if [ ! -f configure ]; then
    echo "==> Running build.sh (autoreconf)"
    ./build.sh
fi

if [ ! -f Makefile ]; then
    echo "==> Configuring libmodsecurity"
    ./configure \
        --prefix="$PREFIX" \
        --without-geoip --without-lua --without-maxmind \
        --without-ssdeep --without-lmdb \
        --disable-doxygen-doc --disable-examples \
        --with-pic
fi

echo "==> Building libmodsecurity"
make -j"$JOBS"
make install

echo "==> libmodsecurity installed to $PREFIX"
ls -la "$PREFIX/lib"/libmodsecurity* 2>/dev/null || ls -la "$PREFIX/lib64"/libmodsecurity* 2>/dev/null || true
