from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from argon2 import PasswordHasher
import os

class CryptoManager:
    def __init__(self):
        self.static_privkey = x25519.X25519PrivateKey.generate()
        self.static_pubkey = self.static_privkey.public_key()
        
        # Ed25519 for signature and verification
        self.signing_key = ed25519.Ed25519PrivateKey.generate()
        
    def get_static_pubkey(self):
        return self.static_pubkey.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def get_signing_pubkey(self):
        return self.signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def perform_key_exchange(self, peer_static_pub, peer_ephemeral_pub, ephemeral_priv=None, salt=None):
        if ephemeral_priv is None:
            ephemeral_priv = x25519.X25519PrivateKey.generate()
        
        shared_secret = ephemeral_priv.exchange(peer_ephemeral_pub)
        
        if salt is None:
            salt = self.get_static_pubkey() + peer_static_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'secure_share_kdf'
        )
        
        print(f"Salt(16-bit): {salt[:16].hex()}")
        derived_key = hkdf.derive(shared_secret)
        return derived_key
    
    def encrypt_file(self, data, key):
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, data, None)
        return nonce + ct
    
    def decrypt_file(self, ciphertext, key):
        if len(ciphertext) < 12:
            raise ValueError("The ciphertext length is too short")
            
        nonce = ciphertext[:12]
        ct = ciphertext[12:]
        
        try:
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ct, None)
            return plaintext
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}, key length: {len(key)}, ciphertext length: {len(ct)}")")
    
    def secure_store(self, data, password):
        ph = PasswordHasher()
        key_hash = ph.hash(password)
        
        key_material = key_hash.split('$')[-1].encode('ascii')[:32]
        if len(key_material) < 32:
            key_material = key_material.ljust(32, b'\0')
        
        chacha = ChaCha20Poly1305(key_material)
        nonce = os.urandom(12)
        return nonce + chacha.encrypt(nonce, data, None)
    
    def hash_file(self, data):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        return digest.finalize()
    
    def sign_file(self, file_data):
        file_hash = self.hash_file(file_data)
        signature = self.signing_key.sign(file_hash)
        return signature
    
    def verify_file(self, file_data, signature, peer_signing_key_pem):
        try:
            # Load verification key from PEM file
            peer_signing_key = serialization.load_pem_public_key(peer_signing_key_pem)
            
            # Compute file hash
            file_hash = self.hash_file(file_data)
            
            # Verify signature
            peer_signing_key.verify(signature, file_hash)
            return True
        except Exception as e:
            print(f"Authentication failed: {e}")
            return False
            
    def export_signing_key(self):
        private_pem = self.signing_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return private_pem
        
    def import_signing_key(self, key_pem):
        self.signing_key = serialization.load_pem_private_key(
            key_pem,
            password=None
        )
    
    def try_decrypt(self, ciphertext, key):
        try:
            return self.decrypt_file(ciphertext, key)
        except:
            return b''