#!/usr/bin/env bash
set -euo pipefail

PREFIX="${PREFIX:-/opt/modsecurity}"
MODSEC_VERSION="${MODSEC_VERSION:-v3.0.15}"
WORKDIR="${WORKDIR:-$(pwd)/vendor}"
JOBS="${JOBS:-$(nproc)}"

mkdir -p "$WORKDIR" "$PREFIX"
cd "$WORKDIR"

# yajl is not in default RHEL/AlmaLinux 8 repos; build from source if missing.
if ! pkg-config --exists yajl 2>/dev/null \
   && [ ! -f "$PREFIX/lib/pkgconfig/yajl.pc" ] \
   && [ ! -f "$PREFIX/lib64/pkgconfig/yajl.pc" ]; then
    echo "==> Building yajl from source"
    if [ ! -d yajl ]; then
        git clone --depth 1 --branch 2.1.0 https://github.com/lloyd/yajl.git
    fi
    cmake -S yajl -B yajl/build \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DCMAKE_POLICY_VERSION_MINIMUM=3.5
    cmake --build yajl/build -j"$JOBS"
    cmake --install yajl/build
fi

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
