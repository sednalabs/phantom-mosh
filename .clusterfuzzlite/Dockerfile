FROM gcr.io/oss-fuzz-base/base-builder:v1

RUN apt-get update && apt-get install -y \
    autoconf automake protobuf-compiler libprotobuf-dev pkg-config \
    zlib1g-dev libncurses5-dev libssl-dev clang lcov

COPY . $SRC/phantom-mosh
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/phantom-mosh
