# Run from epics-base root dir
FROM ubuntu:latest

# Set environment variables
ENV PROJECT_HOME=/opt/epics
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
            build-essential \
            git && \
    mkdir -p ${PROJECT_HOME}

# build EPICS Base
WORKDIR ${PROJECT_HOME}
COPY epics-base ./epics-base
WORKDIR ${PROJECT_HOME}/epics-base
# How many compiler processes to run at once. Each can take most of a gigabyte,
# so a machine with little memory and no swap needs this lowered.
ARG JOBS
RUN make -j${JOBS:-$(nproc)} all

CMD ["/bin/bash"]
