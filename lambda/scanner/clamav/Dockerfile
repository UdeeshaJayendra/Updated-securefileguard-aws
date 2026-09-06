
# ============================================================
# SecureFileGuard Scanner - ClamAV Lambda Container
# ============================================================

# ============================================================
# Stage 1: Build ClamAV 1.5.4 on Amazon Linux 2023
# ============================================================
FROM amazonlinux:2023 AS clamav-builder

ARG CLAMAV_VERSION=1.5.4

# Build dependencies
RUN dnf install -y \
        gcc \
        gcc-c++ \
        make \
        cmake \
        ninja-build \
        pkgconfig \
        rust \
        cargo \
        git \
        tar \
        gzip \
        bzip2 \
        bzip2-devel \
        openssl-devel \
        libcurl-devel \
        libxml2-devel \
        json-c-devel \
        pcre2-devel \
        zlib-devel \
        xz-devel \
        libtool \
        autoconf \
        automake \
        gettext \
        check-devel \
        ncurses-devel \
    && dnf clean all \
    && rm -rf /var/cache/dnf
# Download ClamAV source
WORKDIR /build

RUN curl -L \
    "https://www.clamav.net/downloads/production/clamav-${CLAMAV_VERSION}.tar.gz" \
    -o clamav.tar.gz \
    && tar -xzf clamav.tar.gz \
    && rm clamav.tar.gz

# Enter source directory
WORKDIR /build/clamav-${CLAMAV_VERSION}

# Configure, compile and install ClamAV
RUN mkdir build \
    && cd build \
    && cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/opt/clamav \
        -DENABLE_MILTER=OFF \
        -DENABLE_UNRAR=OFF \
        -DENABLE_EXAMPLES=OFF \
        -DENABLE_TESTS=OFF \
        -DENABLE_DOCS=OFF \
        -DENABLE_CLAMONACC=OFF \
        -DENABLE_FRESHCLAM=ON \
    && cmake --build . --parallel \
    && cmake --install .

# ============================================================
# Stage 2: AWS Lambda Python 3.12 Runtime
# ============================================================
FROM public.ecr.aws/lambda/python:3.12

# Copy compiled ClamAV installation
COPY --from=clamav-builder /opt/clamav /opt/clamav
COPY clamav-db /var/lib/clamav

# Make ClamAV available
ENV PATH="/opt/clamav/bin:${PATH}"
ENV LD_LIBRARY_PATH="/opt/clamav/lib64:/opt/clamav/lib:${LD_LIBRARY_PATH}"

# Copy SecureFileGuard scanner
COPY lambda_function.py ${LAMBDA_TASK_ROOT}/

# Lambda handler
CMD ["lambda_function.lambda_handler"]
