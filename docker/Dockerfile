FROM golang:latest

# Add CA certificates
RUN apt update && apt upgrade -y \
    && apt install ca-certificates libsodium-dev libzmq3-dev libczmq-dev -y \
    && rm -rf /var/lib/apt/lists/

# Add 0mq dependencies
# RUN apk add --no-cache libczmq libzmq libsodium

# Prepare folders needed
WORKDIR /app
RUN mkdir ./conv_rules
RUN mkdir ./config

# Directories described in the configuration file
RUN mkdir ./logs
RUN mkdir ./storage
VOLUME [ "/app/logs", "/app/storage" ]

# In case you use TLS
# ===================
# RUN mkdir /tls
# COPY /path/to/your/certs /app/tls
# COPY /path/to/your/priv_keys /tls

# Copy the engine and its respective config files
COPY ./src .
COPY ./config/engine_config.yml ./config/
COPY ./conv_rules/*.yml ./conv_rules/

RUN go mod download
RUN go build -o slv_engine

# Port to use described in the configuration file
EXPOSE 5555 

 CMD "./slv_engine"

