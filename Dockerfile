# Use Debian 11 as the base image
FROM debian:11

# Install Python 3, pip, git, cmake, OpenSSL development libraries, and Tor
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    git \
    cmake \
    libssl-dev \
    tor \
    && rm -rf /var/lib/apt/lists/*

# Start the Tor service in the background
RUN mkdir /var/run/tor && chown debian-tor /var/run/tor

# Clone and install liboqs-python (only pip install)
RUN git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python && \
    cd liboqs-python && \
    pip3 install .

# Clone PQChat and install its requirements
RUN git clone https://github.com/umutcamliyurt/PQChat.git && \
    cd PQChat && \
    pip3 install -r requirements.txt

# Set the working directory to /PQChat
WORKDIR /PQChat

# Start Tor in the background and run the PQChat application
CMD service tor start && python3 pqchat.py
