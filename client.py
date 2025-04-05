from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from argon2 import PasswordHasher
import os
from zeroconf import ServiceBrowser, ServiceStateChange, ServiceInfo, Zeroconf
import socket
import threading
import pickle

from crypto_utils import CryptoManager

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # doesn't need to succeed
        return s.getsockname()[0]
    except:
        return "127.0.0.1"
    finally:
        s.close()

class SecureShareClient:
    def __init__(self, name, port=8080, enable_networking=True): # for testing purposes

    # def __init__(self, name, port=8080):
        self.port = port
        self.name = name
        self.crypto = CryptoManager()
        self.zeroconf = Zeroconf()
        self.peers = {}
        self.session_keys = {}
        self.peer_signing_keys = {}
        self.pending_download_request = None

        if enable_networking: # for testing purposes
            local_ip = get_local_ip()
            print(f"[DEBUG] Registering service on IP: {local_ip}:{self.port}")
            
            service_info = ServiceInfo(
                "_secure-share._tcp.local.",
                f"{name}._secure-share._tcp.local.",
                addresses=[socket.inet_aton("127.0.0.1")],
                port=self.port,
                properties={"pubkey": self.crypto.get_static_pubkey()}
            )
            self.zeroconf.register_service(service_info)
            
            # Discover other peers
            self.browser = ServiceBrowser(
                self.zeroconf, 
                "_secure-share._tcp.local.", 
                handlers=[self._on_service_state_change]
            )
            
            # Make sure the server is running in a separate thread
            threading.Thread(target=self._start_server, daemon=True).start()
    
    def _on_service_state_change(self, zeroconf, service_type, name, state_change):
        if state_change == ServiceStateChange.Added:
            info = zeroconf.get_service_info(service_type, name)
            if info:
                print(f"Discovered new peer: {name} at {info.parsed_addresses()[0]}:{info.port}")
                peer_pubkey = info.properties[b'pubkey']
                if peer_pubkey != self.crypto.get_static_pubkey():
                    peer_id = peer_pubkey[:8].hex()
                    self.peers[peer_id] = (peer_pubkey, (info.parsed_addresses()[0], info.port))
        elif state_change == ServiceStateChange.Removed:
            peer_id = name.split('.')[0][:8]
            if peer_id in self.peers:
                del self.peers[peer_id]

    def _handle_connection(self, conn):
        try:
            # receive data in a non-blocking way
            data = b''
            chunk = conn.recv(4096)
            while chunk:
                data += chunk
                try:
                    conn.settimeout(0.1)
                    chunk = conn.recv(4096)
                except socket.timeout:
                    break
            
            print(f"Data received, length {len(data)} bytes")
            
            if data.startswith(b'HANDSHAKE'):
                print("Handling handshake request...")
                self._process_handshake(conn, data)
            elif data.startswith(b'FILE_DATA'):
                print("Receiving file data...")
                parts = data.split(b'|', 1)
                if len(parts) == 2:
                    peer_id_bytes = parts[1][:8]  # use the first 8 bits as peer_id
                    peer_id = peer_id_bytes.hex()
                    ciphertext = parts[1][8:]
                    
                    print(f"Sender ID: {peer_id}, Ciphertext length: {len(ciphertext)}")
                    
                    if peer_id in self.session_keys:
                        print(f"Session key found with {peer_id}")
                        session_key = self.session_keys[peer_id]
                        
                        try:
                            print(f"Session key: {session_key.hex()}")
                            print(f"Nonce: {ciphertext[:12].hex()}")
                            print(f"Last 16 bytes of the ciphertext: {ciphertext[12:28].hex()}")
                            
                            plaintext = self.crypto.decrypt_file(ciphertext, session_key)
                            print(f"Decryption succeed, plaintext length: {len(plaintext)}")
                            
                            os.makedirs("received_files", exist_ok=True)
                            with open(f"received_files/{peer_id}_file", 'wb') as f:
                                f.write(plaintext)
                            print(f"File received from {peer_id}")
                        except Exception as decrypt_err:
                            import traceback
                            print(f"Error decrypting file: {decrypt_err}")
                            print(f"Exception:\n{traceback.format_exc()}")
                    else:
                        print(f"No session key with {peer_id}")
                        print(f"List of current session keys: {list(self.session_keys.keys())}")
                else:
                    print("Invalid FILE_DATA format")
            elif data.startswith(b'LIST_FILES'):
                print("Handling file listing requests...")
                parts = data.split(b'|', 1)
                if len(parts) == 2:
                    peer_id_bytes = parts[1]
                    peer_id = peer_id_bytes.hex()
                    
                    # Get the current peer's list of sharable files
                    shared_files = self._get_shared_files()
                    file_list = '\n'.join(shared_files)
                    
                    # Encrypted file list
                    if peer_id in self.session_keys:
                        encrypted_list = self.crypto.encrypt_file(file_list.encode('utf-8'), self.session_keys[peer_id])
                        response = b'FILE_LIST|' + encrypted_list
                        conn.sendall(response)
                        print(f"Sent file list to {peer_id}")
                    else:
                        print(f"No session key with {peer_id}")
                else:
                    print("Invalid FILE_DATA format")
            elif data.startswith(b'KEY_CHANGE'):
                print("Key update notifications...")
                self._process_key_change(conn, data)
            elif data.startswith(b'DOWNLOAD_REQUEST'):
                print("Handling file download requests...")
                parts = data.split(b'|', 2)
                if len(parts) == 3:
                    peer_id_bytes = parts[1]
                    filename = parts[2].decode('utf-8')
                    peer_id = peer_id_bytes.hex()
                    
                    print(f"Receive a download request from {peer_id}, file name: {filename}")
                    
                    # Check if the file exists
                    shared_dir = "shared_files"
                    file_path = os.path.join(shared_dir, filename)
                    
                    if not os.path.exists(file_path):
                        # File does not exist, send a rejection message
                        self._send_download_rejection(peer_id, filename, "file does not exist")
                        print(f"Download request rejected, reason: file does not exist: {file_path}")
                        return
                    
                    self.pending_download_request = (peer_id, filename)
                    print(f"\nPlease confirm the download request: User {peer_id} request to download a file {filename}")
                    print("Type 'approve' to approve the download request, or 'reject' to reject the download request")
                else:
                    print("Invalid download request format")
            elif data.startswith(b'DOWNLOAD_REJECT'):
                print("Download rejection messages...")
                parts = data.split(b'|', 2)
                if len(parts) == 3:
                    peer_id_bytes = parts[1]
                    filename = parts[2].decode('utf-8')
                    peer_id = peer_id_bytes.hex()
                    
                    print(f"Download request for file {filename} denied {peer_id}")
                else:
                    print("Invalid download rejection message format")
            else:
                print(f"Unknown request type: {data[:20]}")
            
        except Exception as e:
            import traceback
            print(f"Error processing connection: {e}")
            print(traceback.format_exc())
        finally:
            conn.close()

    def _get_shared_files(self):
        shared_dir = "shared_files"
        os.makedirs(shared_dir, exist_ok=True)
        
        # return all files in the shared directory
        return [f for f in os.listdir(shared_dir) if os.path.isfile(os.path.join(shared_dir, f))]

    def connect_to_peer(self, address):
        try:
            ip, port = address.split(':') if ':' in address else (address, 8081)
            port = int(port)
            
            with socket.socket() as s:
                s.settimeout(10)
                s.connect((ip, port))
                
                # Create ephemeral key pair
                ephemeral_priv = x25519.X25519PrivateKey.generate()
                ephemeral_pub = ephemeral_priv.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                
                # Send handshake request
                handshake_msg = b'HANDSHAKE|' + self.crypto.get_static_pubkey() + b'|' + ephemeral_pub
                s.sendall(handshake_msg)
                
                # Wait for response
                response = s.recv(1024)
                if b'HANDSHAKE_OK' in response:
                    parts = response.split(b'|', 2)
                    if len(parts) == 3:
                        _, peer_static_pub, peer_eph_pub = parts
                        
                        peer_static_key = x25519.X25519PublicKey.from_public_bytes(peer_static_pub)
                        peer_eph_key = x25519.X25519PublicKey.from_public_bytes(peer_eph_pub)
                        
                        # Private key exchange
                        session_key = self.crypto.perform_key_exchange(
                            peer_static_key, 
                            peer_eph_key,
                            ephemeral_priv,
                            self.crypto.get_static_pubkey() + peer_static_pub
                        )
                        peer_id = peer_static_pub[:8].hex()
                        self.session_keys[peer_id] = session_key
                        
                        print(f"Session established, peer ID: {peer_id}")
                        print(f"Session key: {session_key.hex()}")
                        
                        print(f"Successfully connected to {ip}:{port}")
                    else:
                        raise ConnectionError("Invalid handshake response format")
                else:
                    raise ConnectionError("Handshake failed")
                
        except Exception as e:
            print(f"Connection error: {e}")

    def send_file(self, peer_id, file_path):
        if peer_id not in self.session_keys:
            print("No session with this peer")
            return
        
        with open(file_path, 'rb') as f:
            data = f.read()
        
        signature = self.crypto.sign_file(data)
        
        signing_pubkey = self.crypto.get_signing_pubkey()
        
        # Send file name, file data, file signature, and signed public key as a package
        file_name = os.path.basename(file_path)
        message = {
            "file_name": file_name,
            "file_data": data,
            "signature": signature,
            "signing_pubkey": signing_pubkey
        }
        
        # Serialize the message and
        serialized_data = pickle.dumps(message)
        encrypted = self.crypto.encrypt_file(serialized_data, self.session_keys[peer_id])
        
        my_id_bytes = self.crypto.get_static_pubkey()[:8]
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(self.peers[peer_id][1])
            header = b'FILE_DATA|' + my_id_bytes
            s.sendall(header + encrypted)
            print(f"File sent to {peer_id}")

    def _start_server(self):
        with socket.socket() as s:
            s.bind(('0.0.0.0', self.port))
            print(f"Server started on port {self.port}")
            s.listen()
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self._handle_connection, args=(conn,)).start()

    def _process_handshake(self, conn, data):
        try:
            parts = data.split(b'|', 2)
            if len(parts) != 3:
                raise ValueError("Invalid handshake format")
            
            _, peer_static_pub, peer_eph_pub = parts
            
            # Generate ephemeral key pair
            ephemeral_priv = x25519.X25519PrivateKey.generate()
            my_eph_pub = ephemeral_priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            # Send handshake response
            conn.sendall(b'HANDSHAKE_OK|' + self.crypto.get_static_pubkey() + b'|' + my_eph_pub)
            
            # Perform key exchange
            peer_static_pub_key = x25519.X25519PublicKey.from_public_bytes(peer_static_pub)
            peer_eph_pub_key = x25519.X25519PublicKey.from_public_bytes(peer_eph_pub)
            
            salt = peer_static_pub + self.crypto.get_static_pubkey()
            
            session_key = self.crypto.perform_key_exchange(
                peer_static_pub_key, 
                peer_eph_pub_key,
                ephemeral_priv,
                salt
            )
            
            peer_id = peer_static_pub[:8].hex()
            self.session_keys[peer_id] = session_key
            
            print(f"Session established, peer ID: {peer_id}")
            print(f"Session key: {session_key.hex()}")
            
        except Exception as e:
            print(f"Session Key: {e}")
            conn.close()

    def request_file_list(self, peer_id):
        if peer_id not in self.session_keys:
            raise ValueError("No session established with this peer")
        
        with socket.socket() as s:
            s.connect(self.peers[peer_id][1])
            header = b'LIST_FILES|' + self.crypto.get_static_pubkey()[:8]
            s.sendall(header)
            
            # Receiving Response
            response = s.recv(4096)
            if response.startswith(b'FILE_LIST|'):
                encrypted_data = response[10:]
                plaintext = self.crypto.decrypt_file(encrypted_data, self.session_keys[peer_id])
                file_list = plaintext.decode('utf-8').split('\n')
                return file_list
            else:
                raise ConnectionError("Failed to retrieve file list")

    def _process_key_change(self, conn, data):
        try:
            parts = data.split(b'|', 2)
            if len(parts) != 3:
                raise ValueError("Invalid key change format")
            
            _, old_pubkey, new_pubkey = parts
            
            # Search for the old peer ID and update its public key
            old_peer_id = old_pubkey[:8].hex()
            new_peer_id = new_pubkey[:8].hex()
            
            print(f"Handling key changes: {old_peer_id} -> {new_peer_id}")
            
            if old_peer_id in self.session_keys:

                old_session_key = self.session_keys.pop(old_peer_id)
                
                if old_peer_id in self.peers:
                    peer_addr = self.peers.pop(old_peer_id)[1]
                    
                    self.peers[new_peer_id] = (new_pubkey, peer_addr)
                
                print(f"Peer {old_peer_id} key has been updated, please reconnect to establish a secure session")
                
                conn.sendall(b'KEY_CHANGE_ACK')
            else:
                print(f"Session with {old_peer_id} not found")
        
        except Exception as e:
            print(f"Error processing key change: {e}")

    def regenerate_keys(self):
        old_pubkey = self.crypto.get_static_pubkey()
        old_signing_pubkey = self.crypto.get_signing_pubkey()
        
        self.crypto = CryptoManager()
        
        for peer_id in list(self.session_keys.keys()):
            try:
                self.notify_key_change(peer_id, old_pubkey)
                print(f"{peer_id} being informed key change")
            except Exception as e:
                print(f"Notify key change failure {peer_id}: {e}")
        
        self.session_keys = {}
        self._update_service_info()
        
        return True

    def notify_key_change(self, peer_id, old_pubkey):
        if peer_id not in self.peers:
            return
        
        with socket.socket() as s:
            s.connect(self.peers[peer_id][1])
            msg = b'KEY_CHANGE|' + old_pubkey + b'|' + self.crypto.get_static_pubkey()
            s.sendall(msg)

    def _update_service_info(self):
        # Unregister old services
        self.zeroconf.unregister_all_services()
        local_ip = get_local_ip()
        print(f"[DEBUG] Registering service on local IP: {local_ip}")
        
        # Re-register the service with the new public key
        service_info = ServiceInfo(
            "_secure-share._tcp.local.",
            f"{self.name}._secure-share._tcp.local.",
            addresses=[socket.inet_aton("127.0.0.1")],            
            port=self.port,
            properties={"pubkey": self.crypto.get_static_pubkey()}
        )
        self.zeroconf.register_service(service_info)

    def request_download_file(self, peer_id, filename):
        if peer_id not in self.session_keys:
            raise ValueError("No session established with this peer")
        
        with socket.socket() as s:
            s.connect(self.peers[peer_id][1])
            header = b'DOWNLOAD_REQUEST|' + self.crypto.get_static_pubkey()[:8] + b'|' + filename.encode('utf-8')
            s.sendall(header)
            print(f"Download request sent: {filename}")

    def _send_download_rejection(self, peer_id, filename, reason="User Rejection"):
        try:
            if peer_id in self.peers:
                peer_pubkey, address = self.peers[peer_id]
                
                message = f"DOWNLOAD_REJECTED|{filename}|{reason}".encode('utf-8')
                
                if peer_id in self.session_keys:
                    message = self.crypto.encrypt_file(message, self.session_keys[peer_id])
                    
                # Send message
                with socket.socket() as s:
                    s.connect(address)
                    s.sendall(message)
                    
                print(f"A rejection message has been sent to {peer_id}: {filename}")
            else:
                print(f"Unable to send reject message, unknown peer: {peer_id}")
        except Exception as e:
            print(f"Error sending download rejection message: {e}")

    def send_download_rejection(self, peer_id, filename, reason="User Rejection"):
        self._send_download_rejection(peer_id, filename, reason)

    def _send_file_to_peer(self, peer_id, filename):
        shared_dir = "shared_files"
        file_path = os.path.join(shared_dir, filename)
        
        if not os.path.exists(file_path):
            print(f"File does not exist: {file_path}")
            return
        
        try:
            self.send_file(peer_id, file_path)
            print(f"Sent files {filename} to {peer_id}")
        except Exception as e:
            print(f"Failed to send file: {e}")

    def request_file_from_alternative_peer(self, original_peer_id, filename, alternative_peer_id):
        if alternative_peer_id not in self.session_keys:
            raise ValueError("No session established with alternate peer")
        
        with socket.socket() as s:
            s.connect(self.peers[alternative_peer_id][1])
            header = b'ALT_DOWNLOAD_REQUEST|' + self.crypto.get_static_pubkey()[:8] + b'|' + original_peer_id.encode('utf-8') + b'|' + filename.encode('utf-8')
            s.sendall(header)
            print(f"Alternative download request sent: {filename} (Original peer: {original_peer_id})")

    def save_received_file(self, filename, data, password=None):
        if password:
            # Encrypt with password (which None as default)
            encrypted_data = self.crypto.secure_store(data, password)
            with open(f"received_files/{filename}.enc", "wb") as f:
                f.write(encrypted_data)
        else:
            with open(f"received_files/{filename}", "wb") as f:
                f.write(data)

    def _handle_client(self, client_sock):
        try:
            data = client_sock.recv(4096)
            if not data:
                return
            
            if data.startswith(b'HANDSHAKE|'):
                self._handle_handshake(client_sock, data)
            elif data.startswith(b'FILE_LIST_REQUEST|'):
                self._handle_file_list_request(client_sock, data)
            elif data.startswith(b'FILE_DATA|'):
                self._handle_file_data(client_sock, data)
            elif data.startswith(b'DOWNLOAD_REQUEST|'):
                self._handle_download_request(client_sock, data)
            elif data.startswith(b'DOWNLOAD_REJECTED|') or any(self.crypto.try_decrypt(data, key).startswith(b'DOWNLOAD_REJECTED|') for key in self.session_keys.values()):
                self._handle_download_rejection(client_sock, data)
            elif data.startswith(b'ALT_DOWNLOAD_REQUEST|'):
                self._handle_alt_download_request(client_sock, data)
            elif data.startswith(b'KEY_CHANGE|'):
                self._handle_key_change(client_sock, data)
            else:
                print(f"Unknown message type received: {data[:20]}...")
        except Exception as e:
            print(f"Handling client connection errors: {e}")
        finally:
            client_sock.close()

    def _handle_download_request(self, sock, data):
        try:
            parts = data.split(b'|')
            if len(parts) < 3:
                print("Download request format error")
                return
            
            requester_id = parts[1].hex()
            filename = parts[2].decode('utf-8')
            
            print(f"Received download request from {requester_id}, file: {filename}")
            
            shared_dir = "shared_files"
            file_path = os.path.join(shared_dir, filename)
            
            if not os.path.exists(file_path):
                self._send_download_rejection(requester_id, filename, "File does not exist")
                print(f"Download request rejected, reason: file does not exist: {file_path}")
                return
            

            self.pending_download_request = (requester_id, filename)
            print(f"\nConfirm the download request: User {requester_id} requested to download file {filename}")
            print("Type 'approve' to approve the download request, or 'reject' to reject the download request")
        
        except Exception as e:
            print(f"Error processing download request: {e}")

    def _handle_alt_download_request(self, sock, data):
        try:
            parts = data.split(b'|')
            if len(parts) < 4:
                print("The alternative download request format is incorrect.")
                return
            
            requester_id = parts[1].hex()
            original_peer_id = parts[2].decode('utf-8')
            filename = parts[3].decode('utf-8')
            
            print(f"Received alternate download request from {requester_id} for: {filename} (origin peer: {original_peer_id})")
            
            received_dir = "received_files"
            file_path = os.path.join(received_dir, filename)
            signature_path = os.path.join("signatures", f"{original_peer_id}_{filename}.sig")
            
            if not os.path.exists(file_path) or not os.path.exists(signature_path):
                print(f"The requested file or signature does not exist: {file_path}")
                sock.sendall(b'ALT_DOWNLOAD_REJECT|' + self.crypto.get_static_pubkey()[:8] + b'|' + filename.encode('utf-8'))
                return
            
            # Read file and signature
            with open(file_path, 'rb') as f:
                file_data = f.read()
            with open(signature_path, 'rb') as f:
                signature = f.read()
            
            if requester_id in self.session_keys:
                # Encrypt file
                encrypted = self.crypto.encrypt_file(file_data, self.session_keys[requester_id])
                
                # Send file and signature
                with socket.socket() as s:
                    s.connect(self.peers[requester_id][1])
                    header = b'ALT_FILE_DATA|' + self.crypto.get_static_pubkey()[:8] + b'|' + original_peer_id.encode('utf-8') + b'|' + filename.encode('utf-8') + b'|'
                    sig_header = b'|SIGNATURE|'
                    s.sendall(header + encrypted + sig_header + signature)
                    print(f"Sent alternative file {filename} to {requester_id}")
            else:
                print(f"No session key with requester {requester_id}")
        except Exception as e:
            print(f"Error processing alternate download request: {e}")

    def _handle_file_data(self, sock, data):
        try:
            sig_marker = b'|SIGNATURE|'
            sig_pos = data.find(sig_marker)
            if sig_pos == -1:
                print("File data format error: Signature tag not found")
                return
            
            header_data = data[:data.find(b'|', len(b'FILE_DATA|'))]
            header_parts = header_data.split(b'|')
            if len(header_parts) < 3:
                print("File data format error: insufficient header fields")
                return
            
            peer_id = header_parts[1].hex()
            filename = header_parts[2].decode('utf-8')
            
            # Extract encrypted file data and signature
            encrypted_data = data[len(header_data)+1:sig_pos]
            signature = data[sig_pos+len(sig_marker):]
            
            print(f"Received file {filename} from {peer_id}, data length: {len(encrypted_data)}, signature length: {len(signature)}")
            if peer_id in self.session_keys:
                # Decrypt file
                decrypted_data = self.crypto.decrypt_file(encrypted_data, self.session_keys[peer_id])
                
                os.makedirs("received_files", exist_ok=True)
                os.makedirs("signatures", exist_ok=True)
                
                # Save file and signature
                file_path = os.path.join("received_files", filename)
                with open(file_path, "wb") as f:
                    f.write(decrypted_data)
                    
                # Save the signature and sender's public key for future verification
                sig_path = os.path.join("signatures", f"{peer_id}_{filename}.sig")
                with open(sig_path, "wb") as f:
                    f.write(signature)
                    
                # Save the sender's public key
                if peer_id in self.peer_signing_keys:
                    pubkey_path = os.path.join("keys", f"{peer_id}.pem")
                    os.makedirs("keys", exist_ok=True)
                    with open(pubkey_path, "wb") as f:
                        f.write(self.peer_signing_keys[peer_id])
                    
                print(f"File {filename} saved from {peer_id}")
            else:
                print(f"Received file from unknown peer: {peer_id}")
        except Exception as e:
            print(f"Error processing file data: {e}")

    def _handle_download_rejection(self, sock, data):
        try:
            decrypted = False
            for peer_id, key in self.session_keys.items():
                try:
                    plaintext = self.crypto.decrypt_file(data, key)
                    parts = plaintext.split(b'|')
                    if len(parts) >= 3 and parts[0] == b'DOWNLOAD_REJECTED':
                        filename = parts[1].decode('utf-8')
                        reason = parts[2].decode('utf-8')
                        print(f"Download request denied: {filename}, reason: {reason}")
                        decrypted = True
                        break
                except:
                    continue
            
            if not decrypted:
                print("Received a download rejection message that could not be decrypted")
            
        except Exception as e:
            print(f"Error processing download rejection message: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python client.py [name] [--port PORT]")
        sys.exit(1)
        
    port = 8080
    if '--port' in sys.argv:
        try:
            port = int(sys.argv[sys.argv.index('--port')+1])
        except (ValueError, IndexError):
            print("Invalid port number")
            sys.exit(1)
    
    client = SecureShareClient(sys.argv[1], port=port)
    
    while True:
        try:
            cmd = input("> ")
            if cmd == "quit":
                break
            elif cmd == "list":
                print("Discovered peers:")
                for pid in client.peers:
                    print(f"- {pid}")
            elif cmd.startswith("connect"):
                parts = cmd.split(' ', 1)
                if len(parts) < 2:
                    print("Usage: connect [address]")
                    continue
                _, address = parts
                client.connect_to_peer(address)
            elif cmd.startswith("send"):
                _, peer_id, file_path = cmd.split()
                client.send_file(peer_id, file_path)
            elif cmd.startswith("request_list"):
                _, peer_id = cmd.split()
                try:
                    file_list = client.request_file_list(peer_id)
                    print(f"List of shareable files: {file_list}")
                except Exception as e:
                    print(f"Failed to get file list: {e}")
            elif cmd.startswith("request_download"):
                _, peer_id, filename = cmd.split()
                try:
                    client.request_download_file(peer_id, filename)
                    print(f"Download request sent: {filename}")
                except Exception as e:
                    print(f"Download request failed: {e}")
            elif cmd.startswith("request_alt_download"):
                _, original_peer_id, alt_peer_id, filename = cmd.split()
                try:
                    client.request_file_from_alternative_peer(original_peer_id, filename, alt_peer_id)
                    print(f"Alternative download request sent: {filename} (Original peer: {original_peer_id})")
                except Exception as e:
                    print(f"Alternative download request failed: {e}")
            elif cmd == "update_keys":
                success = client.regenerate_keys()
                if success:
                    print("The key has been updated and all peers have been notified")
                else:
                    print("Update key failed")
            elif cmd.startswith("verify_file"):
                _, file_path, signature_path, pubkey_path = cmd.split()
                try:
                    with open(file_path, 'rb') as f:
                        file_data = f.read()
                    with open(signature_path, 'rb') as f:
                        signature = f.read()
                    with open(pubkey_path, 'rb') as f:
                        pubkey = f.read()
                    
                    is_valid = client.crypto.verify_file(file_data, signature, pubkey)
                    if is_valid:
                        print("File verification successful, integrity and authenticity confirmed")
                    else:
                        print("File verification failed. The file may have been tampered with.")
                except Exception as e:
                    print(f"File verification failed: {e}")
            elif cmd == "approve" or cmd == "yes":
                if client.pending_download_request:
                    peer_id, filename = client.pending_download_request
                    shared_dir = "shared_files"
                    file_path = os.path.join(shared_dir, filename)
                    client.send_file(peer_id, file_path)
                    print(f"Sent file {filename} to {peer_id}")
                    client.pending_download_request = None
                else:
                    print("No pending download requests")
            
            elif cmd == "reject" or cmd == "no":
                if client.pending_download_request:
                    peer_id, filename = client.pending_download_request
                    client._send_download_rejection(peer_id, filename, "User Rejection")
                    print(f"Request from {peer_id} to download {filename} has been denied")
                    client.pending_download_request = None
                else:
                    print("No pending download requests")
            
            elif cmd.startswith("approve ") or cmd.startswith("reject "):
                print("The command format is incorrect. Please enter 'approve' or 'reject' directly to respond to the latest download request")
            
            else:
                print("Unknown command")
        except Exception as e:
            print(f"Error: {str(e)}")