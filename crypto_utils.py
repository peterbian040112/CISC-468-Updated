from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from argon2 import PasswordHasher
import os

class CryptoManager:
    def __init__(self):
        self.static_privkey = x25519.X25519PrivateKey.generate()
        self.static_pubkey = self.static_privkey.public_key()
        
    def get_static_pubkey(self):
        return self.static_pubkey.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def perform_key_exchange(self, peer_static_pub, peer_ephemeral_pub, ephemeral_priv=None, salt=None):
        # If no temporary private key is provided, generate a new one using x25519
        if ephemeral_priv is None:
            ephemeral_priv = x25519.X25519PrivateKey.generate()
        
        # Compute  the shared secret using the ephemeral private key and peer's public key
        shared_secret = ephemeral_priv.exchange(peer_ephemeral_pub)
        
        # If no salt is provided, use the static public key and peer's static public key to create a salt for HKDF
        if salt is None:
            salt = self.get_static_pubkey() + peer_static_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        
        # Use HKDF to derive a key from the shared secret and salt
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'secure_share_kdf'
        )
        
        print(f"Salt(first 16 bits): {salt[:16].hex()}")
        derived_key = hkdf.derive(shared_secret)
        return derived_key
    
    def encrypt_file(self, data, key):
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, data, None)
        return nonce + ct
    
    def decrypt_file(self, ciphertext, key):
        if len(ciphertext) < 12:
            raise ValueError("Ciphertext too short")
            
        nonce = ciphertext[:12]
        ct = ciphertext[12:]
        
        try:
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ct, None)
            return plaintext
        except Exception as e:
            raise ValueError(f"Decryption Failed: {e}, Key Length: {len(key)}, Ciphertext Length: {len(ct)}")
    
    def secure_store(self, data, password):
        ph = PasswordHasher()
        key_hash = ph.hash(password)
        
        key_material = key_hash.split('$')[-1].encode('ascii')[:32]
        if len(key_material) < 32:
            key_material = key_material.ljust(32, b'\0')
        
        chacha = ChaCha20Poly1305(key_material)
        nonce = os.urandom(12)
        return nonce + chacha.encrypt(nonce, data, None)