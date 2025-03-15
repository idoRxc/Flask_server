#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

GO_VERSION="1.21.7"
PYTHON_VERSION="3.9"
INSTALL_DIR="$(pwd)"
SERVER_DIR="$INSTALL_DIR/server"
AGENT_DIR="$INSTALL_DIR/agent"
PROXY_DIR="$INSTALL_DIR/proxy"
FLASK_DIR="$INSTALL_DIR/flask_server"
IMAGERY_DIR="$INSTALL_DIR/imagery_server"
CERTS_DIR="$INSTALL_DIR/certs"

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

install_docker() {
    if command_exists docker; then
        echo -e "${GREEN}Docker is already installed: $(docker --version)${NC}"
    else
        echo "Installing Docker..."
        sudo apt-get update -q
        sudo apt-get install -y docker.io
        sudo systemctl enable docker
        sudo systemctl start docker
        if ! command_exists docker; then
            echo -e "${RED}Failed to install Docker. Please install it manually.${NC}"
            exit 1
        fi
        echo -e "${GREEN}Docker installed${NC}"
    fi
}

install_docker_compose() {
    if command_exists docker-compose; then
        echo -e "${GREEN}Docker Compose is already installed: $(docker-compose --version)${NC}"
    else
        echo "Installing Docker Compose..."
        sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        sudo chmod +x /usr/local/bin/docker-compose
        if ! command_exists docker-compose; then
            echo -e "${RED}Failed to install Docker Compose. Please install it manually.${NC}"
            exit 1
        fi
        echo -e "${GREEN}Docker Compose installed${NC}"
    fi
}

install_openssl() {
    if command_exists openssl; then
        echo -e "${GREEN}OpenSSL is already installed: $(openssl version)${NC}"
    else
        echo "Installing OpenSSL..."
        sudo apt-get update -q
        sudo apt-get install -y openssl
        if ! command_exists openssl; then
            echo -e "${RED}Failed to install OpenSSL. Please install it manually.${NC}"
            exit 1
        fi
        echo -e "${GREEN}OpenSSL installed: $(openssl version)${NC}"
    fi
}

setup_directories() {
    echo "Setting up directories..."
    mkdir -p "$SERVER_DIR" "$AGENT_DIR" "$PROXY_DIR" "$FLASK_DIR" "$IMAGERY_DIR" "$CERTS_DIR"
    mkdir -p "$SERVER_DIR/config" "$AGENT_DIR/config" "$PROXY_DIR/config" "$FLASK_DIR/config" "$IMAGERY_DIR/config"
    mkdir -p "$SERVER_DIR/log" "$AGENT_DIR/log" "$PROXY_DIR/log" "$FLASK_DIR/log" "$IMAGERY_DIR/log"
    mkdir -p "$FLASK_DIR/static" "$IMAGERY_DIR/imagery"
}

generate_certs() {
    echo "Generating certificates in $CERTS_DIR..."
    cd "$CERTS_DIR"
    if [ ! -f "ca.key" ] || [ ! -f "ca.crt" ]; then
        openssl genrsa -out ca.key 2048
        openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.crt -subj "/CN=OSINT-CA"
    fi
    if [ ! -f "server.key" ] || [ ! -f "server.crt" ]; then
        openssl genrsa -out server.key 2048
        openssl req -new -key server.key -out server.csr -subj "/CN=OSINT-Server"
        openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256
        rm server.csr
    fi
    if [ ! -f "agent.key" ] || [ ! -f "agent.crt" ]; then
        openssl genrsa -out agent.key 2048
        openssl req -new -key agent.key -out agent.csr -subj "/CN=OSINT-Agent"
        openssl x509 -req -in agent.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out agent.crt -days 365 -sha256
        rm agent.csr
    fi
    if [ ! -f "client.key" ] || [ ! -f "client.crt" ]; then
        openssl genrsa -out client.key 2048
        openssl req -new -key client.key -out client.csr -subj "/CN=OSINT-Client"
        openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -sha256
        rm client.csr
    fi
    cp server.key imagery_server.key
    cp server.crt imagery_server.crt
    chmod 600 *.key
    cd "$INSTALL_DIR"
    echo -e "${GREEN}Certificates generated${NC}"
}

generate_dockerfiles() {
    echo "Generating Dockerfiles..."

    # Dockerfile for OSINT Server
    cat > "$SERVER_DIR/Dockerfile" << 'EOF'
FROM golang:1.21.7-alpine
WORKDIR /app
COPY server.go .
RUN go build -o server server.go
CMD ["./server"]
EXPOSE 8444
EOF

    # Dockerfile for OSINT Agent
    cat > "$AGENT_DIR/Dockerfile" << 'EOF'
FROM golang:1.21.7-alpine
WORKDIR /app
COPY agent.go .
RUN go build -o agent agent.go
CMD ["./agent"]
EOF

    # Dockerfile for MiddleProxy
    cat > "$PROXY_DIR/Dockerfile" << 'EOF'
FROM python:3.9-slim
WORKDIR /app
COPY proxy.py .
RUN pip install cryptography pyOpenSSL
CMD ["python", "proxy.py"]
EXPOSE 8443
EOF

    # Dockerfile for Flask Server
    cat > "$FLASK_DIR/Dockerfile" << 'EOF'
FROM python:3.9-slim
WORKDIR /app
COPY flask_server.py .
COPY static/ static/
RUN pip install flask cryptography pyOpenSSL redis flask-limiter werkzeug marshmallow tenacity
CMD ["python", "flask_server.py"]
EXPOSE 5000
EOF

    # Dockerfile for Imagery Server
    cat > "$IMAGERY_DIR/Dockerfile" << 'EOF'
FROM python:3.9-slim
WORKDIR /app
COPY imagery_server.py .
RUN pip install flask cryptography pyOpenSSL redis flask-limiter pillow numpy matplotlib torch torchvision marshmallow
CMD ["python", "imagery_server.py"]
EXPOSE 5001
VOLUME /app/imagery
EOF
}

generate_docker_compose() {
    echo "Generating docker-compose.yml..."
    cat > "$INSTALL_DIR/docker-compose.yml" << 'EOF'
version: '3.8'
services:
  redis:
    image: redis:alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data

  osint-server:
    build: ./server
    ports:
      - "8444:8444"
    volumes:
      - ./certs:/app/certs
    depends_on:
      - redis

  osint-agent:
    build: ./agent
    volumes:
      - ./certs:/app/certs
    depends_on:
      - middleproxy

  middleproxy:
    build: ./proxy
    ports:
      - "8443:8443"
    volumes:
      - ./certs:/app/certs
    depends_on:
      - osint-server

  flask-server:
    build: ./flask_server
    ports:
      - "5000:5000"
    volumes:
      - ./certs:/app/certs
      - ./flask_server/log:/app/log
    environment:
      - SECRET_KEY=${SECRET_KEY:-$(openssl rand -hex 32)}
      - REDIS_HOST=redis
      - REDIS_PORT=6379
      - REDIS_DB=0
      - REDIS_SSL=false
      - PROXY_HOST=middleproxy
      - PROXY_PORT=8443
      - OSINT_SERVER_HOST=osint-server
      - OSINT_SERVER_PORT=8444
      - CA_CERT_PATH=/app/certs/ca.crt
      - CERT_PATH=/app/certs/client.crt
      - KEY_PATH=/app/certs/client.key
      - PORT=5000
      - INITIALIZE_ADMIN=true
    depends_on:
      - redis
      - middleproxy

  imagery-server:
    build: ./imagery_server
    ports:
      - "5001:5001"
    volumes:
      - ./certs:/app/certs
      - ./imagery_server/imagery:/app/imagery
      - ./imagery_server/log:/app/log
    environment:
      - ENCRYPTION_KEY=${ENCRYPTION_KEY:-$(openssl rand -hex 32)}
      - SENTINEL_API_KEY=your_sentinel_hub_key
      - API_TOKEN=your_jwt_token_from_flask_login
      - CA_CERT_PATH=/app/certs/ca.crt
      - WHITELISTED_IPS=flask-server
      - IMAGERY_DIR=/app/imagery
      - IMAGERY_SERVER_PORT=5001
      - FLASK_SERVER_URL=http://flask-server:5000
      - FLASK_ENV=production
      - SSL_CERT_PATH=/app/certs/imagery_server.crt
      - SSL_KEY_PATH=/app/certs/imagery_server.key
    depends_on:
      - flask-server

volumes:
  redis-data:
EOF
}

check_source_files() {
    echo "Checking for required source files..."
    for file in "$SERVER_DIR/server.go" "$AGENT_DIR/agent.go" "$PROXY_DIR/proxy.py" "$FLASK_DIR/flask_server.py" "$IMAGERY_DIR/imagery_server.py"; do
        if [ ! -f "$file" ]; then
            echo -e "${RED}Error: $file is missing. Please add your actual implementation before running this script.${NC}"
            exit 1
        fi
    done
    echo -e "${GREEN}All required source files found${NC}"
}

main() {
    echo "Starting setup..."
    install_docker
    install_docker_compose
    install_openssl
    setup_directories
    generate_certs
    check_source_files  # Ensure all source files are present
    generate_dockerfiles
    generate_docker_compose
    echo "Building and starting Docker containers..."
    docker-compose up --build -d
    echo -e "${GREEN}Setup complete!${NC}"
    echo "Containers are running. Check logs with:"
    echo "  docker-compose logs [service_name] (e.g., flask-server, imagery-server)"
    echo "To stop: docker-compose down"
    echo "Note: Update SENTINEL_API_KEY and API_TOKEN in docker-compose.yml after Flask login."
}

main