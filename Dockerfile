# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2023 Intel Corporation.

FROM fedora:38

# Setup container to build CNDP applications
RUN dnf -y upgrade && dnf -y install \
    @development-tools \
    libbsd-devel \
    json-c-devel \
    libnl3-devel \
    libnl3-cli \
    numactl-libs \
    libbpf-devel \
    libbpf \
    meson \
    ninja-build \
    gcc-c++ \
    libpcap \
    libpcap-devel \
    golang \
    clang \
    llvm \
    m4 \
    bpftool 
RUN dnf groupinstall -y 'Development Tools'
RUN dnf -y install git libbsd-devel json-c-devel libnl3-devel libnl3-cli     numactl-libs libbpf-devel libbpf meson ninja-build gcc-c++     libpcap libpcap-devel libxdp-devel libxdp
RUN dnf -y install numactl-devel
RUN dnf -y install python3-pyelftools
RUN dnf -y install python38
RUN git clone https://github.com/DPDK/dpdk.git
WORKDIR dpdk/
RUN git checkout v23.03
RUN meson setup build
RUN ninja -C build
RUN dnf -y install iproute
