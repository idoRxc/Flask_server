#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

GO_VERSION="1.21.7"
GO_URL="https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz"
PYTHON_VERSION="3.9"
INSTALL_DIR="$(pwd)"
SERVER_DIR="$INSTALL_DIR/server"
AGENT_DIR="$INSTALL_DIR/agent"
PROXY_DIR="$INSTALL_DIR/proxy"
FLASK_DIR="$INSTALL_DIR/flask_server"
CERTS_DIR="$INSTALL_DIR/certs"

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

install_go() {
    if command_exists go; then
        echo -e "${GREEN}Go is already installed: $(go version)${NC}"
    else
        echo "Installing Go $GO_VERSION..."
        wget -q "$GO_URL" -O go.tar.gz
        sudo tar -C /usr/local -xzf go.tar.gz
        echo "export PATH=\$PATH:/usr/local/go/bin" >> ~/.bashrc
        export PATH=$PATH:/usr/local/go/bin
        rm go.tar.gz
        if ! command_exists go; then
            echo -e "${RED}Failed to install Go. Please install it manually.${NC}"
            exit 1
        fi
        echo -e "${GREEN}Go installed: $(go version)${NC}"
    fi
}

install_python() {
    if command_exists python3 && python3 --version | grep -q "Python $PYTHON_VERSION"; then
        echo -e "${GREEN}Python $PYTHON_VERSION or higher is already installed: $(python3 --version)${NC}"
    else
        echo "Installing Python $PYTHON_VERSION..."
        sudo apt-get update -q
        sudo apt-get install -y python3 python3-pip python3-dev
        if ! command_exists python3; then
            echo -e "${RED}Failed to install Python. Please install it manually.${NC}"
            exit 1
        fi
        echo -e "${GREEN}Python installed: $(python3 --version)${NC}"
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

install_redis() {
    if command_exists redis-server; then
        echo -e "${GREEN}Redis is already installed: $(redis-server --version)${NC}"
    else
        echo "Installing Redis..."
        sudo apt-get update -q
        sudo apt-get install -y redis-server
        if ! command_exists redis-server; then
            echo -e "${RED}Failed to install Redis. Please install it manually.${NC}"
            exit 1
        fi
        sudo systemctl enable redis-server
        sudo systemctl start redis-server
        echo -e "${GREEN}Redis installed and started${NC}"
    fi
}

install_python_deps() {
    echo "Installing Python dependencies..."
    pip3 install --upgrade pip
    pip3 install flask cryptography pyOpenSSL redis flask-limiter werkzeug marshmallow tenacity
    echo -e "${GREEN}Python dependencies installed${NC}"
}

setup_directories() {
    echo "Setting up directories..."
    mkdir -p "$SERVER_DIR" "$AGENT_DIR" "$PROXY_DIR" "$FLASK_DIR" "$CERTS_DIR"
    mkdir -p "$SERVER_DIR/config" "$AGENT_DIR/config" "$PROXY_DIR/config" "$FLASK_DIR/config" "$FLASK_DIR/static"
    mkdir -p "$SERVER_DIR/log" "$AGENT_DIR/log" "$PROXY_DIR/log" "$FLASK_DIR/log"
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
    chmod 600 *.key
    cd "$INSTALL_DIR"
    echo -e "${GREEN}Certificates generated${NC}"
}

generate_flask_env() {
    echo "Generating Flask environment file..."
    cat > "$FLASK_DIR/.env" << EOF
SECRET_KEY=$(openssl rand -hex 32)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
REDIS_SSL=false
PROXY_HOST=0.0.0.0
PROXY_PORT=8443
OSINT_SERVER_HOST=0.0.0.0
OSINT_SERVER_PORT=8444
CA_CERT_PATH=$CERTS_DIR/ca.crt
CERT_PATH=$CERTS_DIR/client.crt
KEY_PATH=$CERTS_DIR/client.key
PORT=5000
INITIALIZE_ADMIN=true
EOF
    echo -e "${GREEN}Flask environment file generated at $FLASK_DIR/.env${NC}"
}

copy_source_code() {
    echo "Copying source code..."
    if [ ! -f "$SERVER_DIR/server.go" ]; then
        cat > "$SERVER_DIR/server.go" << 'EOF'
package main
import "log"
func main() { log.Fatal("Server placeholder - replace with actual code") }
EOF
    fi
    if [ ! -f "$AGENT_DIR/agent.go" ]; then
        cat > "$AGENT_DIR/agent.go" << 'EOF'
package main
import "log"
func main() { log.Fatal("Agent placeholder - replace with actual code") }
EOF
    fi
    if [ ! -f "$PROXY_DIR/proxy.py" ]; then
        cat > "$PROXY_DIR/proxy.py" << 'EOF'
[Insert your MiddleProxy code here]
EOF
    fi
    if [ ! -f "$FLASK_DIR/flask_server.py" ]; then
        cat > "$FLASK_DIR/flask_server.py" << 'EOF'
[Insert your Flask server code here]
EOF
    fi
    if [ ! -f "$FLASK_DIR/static/index.html" ]; then
        cat > "$FLASK_DIR/static/index.html" << 'EOF'
<!DOCTYPE html>
<html>
<head><title>OSINT Dashboard</title></head>
<body><h1>Welcome to OSINT Dashboard</h1></body>
</html>
EOF
    fi
}

compile_go_programs() {
    echo "Compiling Go programs..."
    cd "$SERVER_DIR"
    go build -o server server.go
    cd "$AGENT_DIR"
    go build -o agent agent.go
    cd "$INSTALL_DIR"
    echo -e "${GREEN}Go programs compiled${NC}"
}

main() {
    echo "Starting setup..."
    install_go
    install_python
    install_openssl
    install_redis
    install_python_deps
    setup_directories
    generate_certs
    generate_flask_env
    copy_source_code
    compile_go_programs
    echo -e "${GREEN}Setup complete!${NC}"
    echo "To run the components:"
    echo "  1. Start the OSINT Server: cd $SERVER_DIR && ./server config/server.yaml"
    echo "  2. Start the OSINT Agent: cd $AGENT_DIR && ./agent config/agent.yaml"
    echo "  3. Start the MiddleProxy: cd $PROXY_DIR && python3 proxy.py"
    echo "  4. Start the Flask Server: cd $FLASK_DIR && source .env && python3 flask_server.py"
    echo "Note: Ensure Redis is running (sudo systemctl start redis-server) and replace placeholder code with actual implementations."
}

main
