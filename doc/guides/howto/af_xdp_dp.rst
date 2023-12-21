.. SPDX-License-Identifier: BSD-3-Clause
   Copyright(c) 2023 Intel Corporation.

Using the AF_XDP Device Plugin with the AF_XDP driver
=====================================================

Introduction
------------

The `AF_XDP Device Plugin for Kubernetes`_ is a project that provisions
and advertises interfaces (that can be used with AF_XDP) to Kubernetes.
The project also includes a `CNI`_.

AF_XDP is a Linux socket Address Family that enables an XDP program
to redirect packets to a memory buffer in userspace.

This document explains how to use the `AF_XDP Device Plugin for Kubernetes`_ with
a DPDK :doc:`../nics/af_xdp` based application running in a Pod.

.. _AF_XDP Device Plugin for Kubernetes: https://github.com/intel/afxdp-plugins-for-kubernetes
.. _CNI: https://github.com/containernetworking/cni

Background
----------

The standard :doc:`../nics/af_xdp` initialization process involves loading an eBPF program
onto the Kernel netdev to be used by the PMD.
This operation requires root or escalated Linux privileges
and prevents the PMD from working in an unprivileged container.
The AF_XDP Device Plugin (DP) addresses this situation
by providing an entity that manages eBPF program
lifecycle for Pod interfaces that wish to use AF_XDP, this in turn allows
the pod to be used without privilege escalation.

In order for the pod to run without privilege escalation, the AF_XDP DP
creates a Unix Domain Socket (UDS) and listens for Pods to make requests
for XSKMAP(s) File Descriptors (FDs) for interfaces in their network namespace.
In other words, the DPDK application running in the Pod connects to this UDS and
initiates a "handshake" to retrieve the XSKMAP(s) FD(s). Upon a successful "handshake",
the DPDK application receives the FD(s) for the XSKMAP(s) associated with the relevant
netdevs. The DPDK application can then create the AF_XDP socket(s), and attach
the socket(s) to the netdev queue(s) by inserting the socket(s) into the XSKMAP(s).

The EAL vdev argument ``uds_path`` is used to indicate that the user wishes
to run the AF_XDP PMD in unprivileged mode and to receive the XSKMAP FD
from the AF_XDP DP.
When this param is used, the
``XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD`` libbpf flag
is used when creating the AF_XDP socket
to instruct libbpf/libxdp not to load the default eBPF redirect
program for AF_XDP on the netdev. Instead the lifecycle management of the eBPF
program is handled by the AF_XDP DP.

.. note::

   The UDS file path inside the pod appears at "/tmp/afxdp_dp/<netdev>/afxdp.sock".

Prerequisites
-------------

Device Plugin and DPDK container prerequisites:

* Create a DPDK container image.

* Set up the device plugin and prepare the Pod Spec as described in
  the instructions for `AF_XDP Device Plugin for Kubernetes`_.

* Increase locked memory limit so containers have enough memory for packet buffers.
  For example:

  .. code-block:: console

     cat << EOF | sudo tee /etc/systemd/system/containerd.service.d/limits.conf
     [Service]
     LimitMEMLOCK=infinity
     EOF

* dpdk-testpmd application should have AF_XDP feature enabled.

  For further information see the docs for the: :doc:`../../nics/af_xdp`.


Example
-------

How to run dpdk-testpmd with the AF_XDP Device plugin:

* Clone the AF_XDP Device plugin

  .. code-block:: console

     # git clone https://github.com/intel/afxdp-plugins-for-kubernetes.git

* Build the AF_XDP Device plugin and the CNI

  .. code-block:: console

     # cd afxdp-plugins-for-kubernetes/
     # make image

* Make sure to modify the image used by the `daemonset.yml`_ file in the deployments directory with
  the following configuration:

   .. _daemonset.yml : https://github.com/intel/afxdp-plugins-for-kubernetes/blob/main/deployments/daemonset.yml

  .. code-block:: yaml

    image: afxdp-device-plugin:latest

  .. note::

    This will select the AF_XDP DP image that was built locally. Detailed configuration
    options can be found in the AF_XDP Device Plugin `readme`_ .

  .. _readme: https://github.com/intel/afxdp-plugins-for-kubernetes#readme

* Deploy the AF_XDP Device Plugin and CNI

  .. code-block:: console

    # kubectl create -f deployments/daemonset.yml

* Create a Network Attachment Definition (NAD)

  .. code-block:: console

    # kubectl create -f nad.yaml

  Sample nad.yml

  .. code-block:: yaml

    apiVersion: "k8s.cni.cncf.io/v1"
    kind: NetworkAttachmentDefinition
    metadata:
      name: afxdp-network
      annotations:
        k8s.v1.cni.cncf.io/resourceName: afxdp/myPool
    spec:
      config: '{
          "cniVersion": "0.3.0",
          "type": "afxdp",
          "mode": "primary",
          "logFile": "afxdp-cni.log",
          "logLevel": "debug",
          "ethtoolCmds" : ["-N -device- rx-flow-hash udp4 fn",
                           "-N -device- flow-type udp4 dst-port 2152 action 22"
                        ],
          "ipam": {
            "type": "host-local",
            "subnet": "192.168.1.0/24",
            "rangeStart": "192.168.1.200",
            "rangeEnd": "192.168.1.220",
            "routes": [
              { "dst": "0.0.0.0/0" }
            ],
            "gateway": "192.168.1.1"
          }
        }'

  For further reference please use the example provided by the AF_XDP DP `nad.yaml`_

  .. _nad.yaml: https://github.com/intel/afxdp-plugins-for-kubernetes/blob/main/examples/network-attachment-definition.yaml

* Build a DPDK container image (using Docker)

  .. code-block:: console

    # docker build -t dpdk -f Dockerfile .

  Sample Dockerfile (should be placed in top level DPDK directory):

  .. code-block:: console

    FROM fedora:38

    # Setup container to build DPDK applications
    RUN dnf -y upgrade && dnf -y install \
        libbsd-devel \
        numactl-libs \
        libbpf-devel \
        libbpf \
        meson \
        ninja-build \
        libxdp-devel \
        libxdp \
        numactl-devel \
        python3-pyelftools \
        python38 \
        iproute
    RUN dnf groupinstall -y 'Development Tools'

    # Create DPDK dir and copy over sources
    WORKDIR /dpdk
    COPY app app
    COPY builddir  builddir
    COPY buildtools buildtools
    COPY config config
    COPY devtools devtools
    COPY drivers drivers
    COPY dts dts
    COPY examples examples
    COPY kernel kernel
    COPY lib lib
    COPY license license
    COPY MAINTAINERS MAINTAINERS
    COPY Makefile Makefile
    COPY meson.build meson.build
    COPY meson_options.txt meson_options.txt
    COPY usertools usertools
    COPY VERSION VERSION
    COPY ABI_VERSION ABI_VERSION
    COPY doc doc

    # Build DPDK
    RUN meson setup build
    RUN ninja -C build

  .. note::

    Ensure the Dockerfile is placed in the top level DPDK directory.

* Run the Pod

  .. code-block:: console

     # kubectl create -f pod.yaml

  Sample pod.yaml:

  .. code-block:: yaml

    apiVersion: v1
    kind: Pod
    metadata:
     name: dpdk
     annotations:
       k8s.v1.cni.cncf.io/networks: afxdp-network
    spec:
      containers:
      - name: testpmd
        image: dpdk:latest
        command: ["tail", "-f", "/dev/null"]
        securityContext:
          capabilities:
            add:
              - NET_RAW
              - IPC_LOCK
        resources:
          requests:
            afxdp/myPool: '1'
          limits:
            hugepages-1Gi: 2Gi
            cpu: 2
            memory: 256Mi
            afxdp/myPool: '1'
        volumeMounts:
        - name: hugepages
          mountPath: /dev/hugepages
      volumes:
      - name: hugepages
        emptyDir:
          medium: HugePages

  For further reference please use the `pod.yaml`_

  .. _pod.yaml: https://github.com/intel/afxdp-plugins-for-kubernetes/blob/main/examples/pod-spec.yaml

.. note::

   For Kernel versions older than 5.19 `CAP_BPF` is also required in
   the container capabilities stanza.

* Run DPDK with a command like the following:

  .. code-block:: console

     kubectl exec -i dpdk --container testpmd -- \
           ./build/app/dpdk-testpmd -l 0-2 --no-pci --main-lcore=2 \
           --vdev net_af_xdp,iface=<interface name>,start_queue=22,queue_count=1,uds_path=/tmp/afxdp_dp/<interface-name>/afxdp.sock \
           -- -i --a --nb-cores=2 --rxq=1 --txq=1 --forward-mode=macswap;
