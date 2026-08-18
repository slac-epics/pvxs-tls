ARG DOCKER_REGISTRY=ghcr.io
ARG DOCKER_USERNAME=slac-epics
ARG BASE_IMAGE=epics-base
ARG BASE_IMAGE_TAG=latest

FROM ${DOCKER_REGISTRY}/${DOCKER_USERNAME}/${BASE_IMAGE}:${BASE_IMAGE_TAG}

# Set environment variables
ENV PROJECT_HOME=/opt/epics
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
            openssl \
            libssl-dev \
            libevent-dev \
            libcurl4-openssl-dev \
            pkg-config

# VCS_VERSION carries `git describe` in from the host: .dockerignore keeps .git
# out of the build context (its bookkeeping churns constantly and would wreck the
# layer cache), but without it the built library could not say which commit it is.
# Record it in CONFIG_SITE.local rather than on one make command line, so images
# built on top of this one that rebuild the tree inherit it too.
ARG VCS_VERSION=unknown

# Set up RELEASE.local
WORKDIR ${PROJECT_HOME}
RUN echo "GENVERSIONDEFAULT = ${VCS_VERSION}" >> ${PROJECT_HOME}/CONFIG_SITE.local
RUN echo "EPICS_BASE = \$(TOP)/../epics-base" >> ${PROJECT_HOME}/RELEASE.local

# build PVXS
WORKDIR ${PROJECT_HOME}/pvxs
COPY . .
# How many compiler processes to run at once. Each can take most of a gigabyte,
# so a machine with little memory and no swap needs this lowered.
ARG JOBS
RUN make -j${JOBS:-$(nproc)} all

CMD ["/bin/bash"]
