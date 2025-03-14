import socket 
import threading
import ssl
import json
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import OpenSSL.crypto


class MiddleProxy:
    def __init__(self, server_host, server_port, proxy_host, proxy_port):
        self.server_host = server_host
        self.server_port = server_port
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.active_connections = {}
        self.lock = threading.Lock()
        self.encryption_keys = {}
        self.server_certs = None
        self.client_certs = None
        self.request_history = {}
        
        self.ssl_protocols = ssl.PROTOCOL_TLS_SERVER
        self.cipher_suite = (
            'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:'
            'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:'
            'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256'
        )

    def fetch_certificates(self):
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((self.server_host, self.server_port))
            server_context = ssl.create_default_context()
            server_ssl = server_context.wrap_socket(server_socket, server_hostname=self.server_host)
            self.server_certs = server_ssl.getpeercert(binary_form=True)
            server_socket.close()

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.proxy_host, self.proxy_port))
            client_context = ssl.create_default_context()
            client_ssl = client_context.wrap_socket(client_socket, server_hostname=self.proxy_host)
            self.client_certs = client_ssl.getpeercert(binary_form=True)
            client_socket.close()

            print("Successfully fetched certificates from server and client")
            return True
        except Exception as e:
            print(f"Error fetching certificates: {e}")
            return False

    def generate_encryption_key(self, connection_id):
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(str(connection_id).encode()))
        return Fernet(key), salt

    def start(self):
        if not self.fetch_certificates():
            raise Exception("Failed to fetch certificates")

        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        if self.server_certs and self.client_certs:
            self.ssl_context.load_verify_locations(cadata=self.server_certs)
            self.ssl_context.load_verify_locations(cadata=self.client_certs)
        
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED
        self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.ssl_context.set_ciphers(self.cipher_suite)
        
        self.ssl_context.options |= ssl.OP_NO_COMPRESSION 
        self.ssl_context.options |= ssl.OP_SINGLE_DH_USE 
        self.ssl_context.options |= ssl.OP_SINGLE_ECDH_USE
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.server_host, self.server_port))
        self.server_socket.listen(5)
        print(f"Secure proxy server listening on {self.server_host}:{self.server_port}")

    def accept_connections(self):
        while True:
            client_socket, client_address = self.server_socket.accept()
            print(f"Accepted connection from {client_address}")
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()

    def handle_client(self, client_socket):
        try:
            ssl_client = self.ssl_context.wrap_socket(client_socket, server_side=True)
            
            # Receive and verify certificates
            cert_data = ssl_client.recv(4096)
            if not self.verify_certificates(cert_data):
                print("Certificate verification failed")
                ssl_client.close()
                return

            cert = ssl_client.getpeercert()
            if not cert:
                print("No certificate received from client")
                ssl_client.close()
                return

            connection_id = hash(str(cert))
            cipher, salt = self.generate_encryption_key(connection_id)
            
            with self.lock:
                self.encryption_keys[connection_id] = cipher

            ssl_client.send(salt)
            self.handle_backend(ssl_client, cert, connection_id)

        except ssl.SSLError as e:
            print(f"SSL Error: {e}")
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            self.cleanup_connection(connection_id)
            client_socket.close()

    def verify_certificates(self, cert_data):
        try:
            cert_info = json.loads(cert_data.decode())
            if not all(key in cert_info for key in ['cert', 'key', 'ca']):
                print("Missing required certificate data")
                return False

            self.session_certs = cert_info
            
            try:
                cert = OpenSSL.crypto.load_certificate(
                    OpenSSL.crypto.FILETYPE_PEM, 
                    cert_info['cert']
                )
                ca_cert = OpenSSL.crypto.load_certificate(
                    OpenSSL.crypto.FILETYPE_PEM, 
                    cert_info['ca']
                )
                
                store = OpenSSL.crypto.X509Store()
                store.add_cert(ca_cert)
                store_ctx = OpenSSL.crypto.X509StoreContext(store, cert)
                store_ctx.verify_certificate()
                
                print("Certificate verification successful")
                return True
                
            except OpenSSL.crypto.X509StoreContextError as e:
                print(f"Certificate verification failed: {e}")
                return False
                
        except json.JSONDecodeError:
            print("Invalid certificate data format")
            return False
        except Exception as e:
            print(f"Certificate verification error: {e}")
            return False

    def handle_backend(self, client_ssl, cert, connection_id):
        try:
            backend_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            backend_context = ssl.create_default_context()
            backend_context.load_verify_locations(cafile='./ca.crt')
            backend_context.load_cert_chain(certfile='./client.crt', keyfile='./client.key')
            backend_context.minimum_version = ssl.TLSVersion.TLSv1_3
            backend_context.set_ciphers(self.cipher_suite)
            
            backend_ssl = backend_context.wrap_socket(
                backend_socket,
                server_hostname=self.proxy_host
            )
            backend_ssl.connect((self.proxy_host, self.proxy_port))

            with self.lock:
                self.active_connections[connection_id] = {
                    'client': client_ssl,
                    'backend': backend_ssl
                }

            client_thread = threading.Thread(
                target=self.relay_data,
                args=(client_ssl, backend_ssl, connection_id, "client->backend")
            )
            backend_thread = threading.Thread(
                target=self.relay_data,
                args=(backend_ssl, client_ssl, connection_id, "backend->client")
            )

            client_thread.start()
            backend_thread.start()

            client_thread.join()
            backend_thread.join()

        except Exception as e:
            print(f"Error in backend handling: {e}")
        finally:
            self.cleanup_connection(connection_id)

    def encrypt_data(self, data, connection_id):
        with self.lock:
            cipher = self.encryption_keys.get(connection_id)
            if cipher:
                return cipher.encrypt(data)
        return data

    def decrypt_data(self, data, connection_id):
        with self.lock:
            cipher = self.encryption_keys.get(connection_id)
            if cipher:
                return cipher.decrypt(data)
        return data

    def relay_data(self, source, destination, connection_id, direction):
        try:
            while True:
                data = source.recv(4096)
                if not data:
                    break

                if direction == "client->backend":
                    data = self.encrypt_data(data, connection_id)
                else:
                    data = self.decrypt_data(data, connection_id)

                try:
                    decoded = data.decode('utf-8').strip()
                    json_data = json.loads(decoded)
                    print(f"{direction} JSON: {json.dumps(json_data, indent=2)}")
                except (json.JSONDecodeError, UnicodeDecodeError):
                    print(f"{direction} RAW: {len(data)} bytes")

                destination.send(data)

        except Exception as e:
            print(f"Error in {direction}: {e}")
        finally:
            self.cleanup_connection(connection_id)

    def cleanup_connection(self, connection_id):
        with self.lock:
            if connection_id in self.active_connections:
                try:
                    self.active_connections[connection_id]['client'].close()
                    self.active_connections[connection_id]['backend'].close()
                except:
                    pass
                del self.active_connections[connection_id]
            if connection_id in self.encryption_keys:
                del self.encryption_keys[connection_id]

    def cleanup(self):
        with self.lock:
            for connection in self.active_connections.values():
                try:
                    connection['client'].close()
                    connection['backend'].close()
                except:
                    pass
            self.active_connections.clear()
            self.encryption_keys.clear()
        self.server_socket.close()
    
    def log_all_connections(self):
        try:
            with open('connection_log.txt', 'w') as f:
                for connection_id, connection in self.active_connections.items():
                    f.write(f"Connection {connection_id}:\n")
                    f.write(f"  Client: {connection['client'].getpeername()}\n")
                    f.write(f"  Backend: {connection['backend'].getpeername()}\n")
                    f.write(f"  Encryption Key: {self.encryption_keys[connection_id]}\n")
                    f.write(f"  Client Certificate: {connection['client'].getpeercert()}\n")
                    f.write(f"  Backend Certificate: {connection['backend'].getpeercert()}\n")
                    f.write(f"  Client SNI: {connection['client'].getpeername()}\n")
                    f.write(f"  Backend SNI: {connection['backend'].getpeername()}\n")
                    f.close()
            
            print("All connections logged successfully.")

        except Exception as e:
            print(f"Error logging connections: {e}")

    def shutdown(self):
        self.server_socket.close()
        self.cleanup()
        print("Proxy server shut down.")

    def ping_client_and_backend(self):
        try:
            for connection_id, connection in self.active_connections.items():
                client_socket = connection['client']
                backend_socket = connection['backend']
                
                client_socket.sendall(b'PING')
                backend_socket.sendall(b'PING')

                client_response = client_socket.recv(1024)
                backend_response = backend_socket.recv(1024)

                if client_response != b'PONG' or backend_response != b'PONG':
                    print(f"Connection {connection_id} is not responding.")
                    self.cleanup_connection(connection_id)
                    self.log_all_connections()
                    self.shutdown()
                    break
        except Exception as e:
            print(f"Error pinging client and backend: {e}") 


    def mapping_network_traffic(self):
        try:
            while True:
                data = self.server_socket.recv(4096)
                if not data:
                    break
                
                if data.startswith(b'GET /'):
                    self.handle_web_request(data)
                else:
                    self.handle_other_traffic(data)
        except Exception as e:
            print(f"Error mapping network traffic: {e}")
        

    def Id_malicious_traffic(self, data):
        try:
            if self.block_malicious_traffic(data):
                return True
            return False
        except Exception as e:
            print(f"Error in malicious traffic detection: {e}")
            return False
            

    def block_malicious_traffic(self, data):
        try:
            malicious_patterns = [
                b'../../../',  
                b'SELECT',     
                b'<script',    
                b'eval(',      
                b'exec(',      
            ]

            if isinstance(data, str):
                data = data.encode()

            for pattern in malicious_patterns:
                if pattern in data.lower():
                    print(f"Blocked malicious traffic containing pattern: {pattern}")
                    return True

            if len(data) > 1024 * 1024:  # 1MB limit
                print("Blocked unusually large payload")
                return True

            current_time = time.time()
            client_ip = self.server_socket.getpeername()[0]
            
            if client_ip in self.request_history:
                if current_time - self.request_history[client_ip] < 1:  # Less than 1 second
                    print(f"Blocked potential DoS attack from {client_ip}")
                    return True
            
            self.request_history[client_ip] = current_time

            return False 

        except Exception as e:
            print(f"Error in malicious traffic detection: {e}")
            return False
          
    def handle_web_request(self, data):
        try:
            request = data.decode('utf-8')
            request_line = request.split('\n')[0]
            method, path, protocol = request_line.split()
            print(f"Handling web request: {path}")

            # Check for malicious patterns
            if self.Id_malicious_traffic(data):
                return None

            # Parse headers
            headers = {}
            for line in request.split('\n')[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()

            # Log request details
            print(f"Method: {method}")
            print(f"Path: {path}") 
            print(f"Protocol: {protocol}")
            print(f"Headers: {headers}")

            return data

        except Exception as e:
            print(f"Error handling web request: {e}")
            return None

    def handle_other_traffic(self, data):
        try:
            print(f"Handling other traffic: {len(data)} bytes")
            # Add your other traffic handling logic here
        except Exception as e:
            print(f"Error handling other traffic: {e}")

if __name__ == '__main__':
    LISTEN_HOST = '0.0.0.0'  # Host address where the proxy listens for incoming connections
    LISTEN_PORT = 8443       # Port where the proxy listens for incoming connections
    BACKEND_HOST = '192.168.1.100'  # Address of the actual backend server
    BACKEND_PORT = 8444      # Port of the actual backend server

    cert_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'certs')
    
    ca_cert = os.path.join(cert_dir, 'ca.crt')
    client_cert = os.path.join(cert_dir, 'client.crt')
    client_key = os.path.join(cert_dir, 'client.key')

    for cert_file in [ca_cert, client_cert, client_key]:
        if not os.path.exists(cert_file):
            raise FileNotFoundError(f"Certificate file not found: {cert_file}")

    proxy = MiddleProxy(
        server_host=LISTEN_HOST,
        server_port=LISTEN_PORT,
        proxy_host=BACKEND_HOST,
        proxy_port=BACKEND_PORT
    )
    try:
        print("Starting proxy server...")
        print(f"Using certificates from: {cert_dir}")
        proxy.start()
        print(f"Proxy listening on {LISTEN_HOST}:{LISTEN_PORT}")
        print(f"Forwarding to {BACKEND_HOST}:{BACKEND_PORT}")
        proxy.accept_connections()
    except KeyboardInterrupt:
        print("\nShutting down proxy server...")
        proxy.cleanup()
    except Exception as e:
        print(f"Error: {e}")
        proxy.cleanup()