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
RUN make -j10 all

CMD ["/bin/bash"]
