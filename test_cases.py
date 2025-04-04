import unittest
import os
from client import SecureShareClient
import time

class TestSecureShareClientErrors(unittest.TestCase):
    def setUp(self):
        self.client = SecureShareClient("TestClient", port=9999, enable_networking=False)
        time.sleep(0.1)


    def test_send_file_to_unknown_peer(self):
        # Attempt to send a file to a peer with no session established
        try:
            self.client.send_file("nonexistent_peer", "nonexistent_file.txt")
            print("[TEST] Expected error: No session with this peer")
        except Exception as e:
            self.fail(f"send_file raised unexpected exception: {e}")

    def test_decrypt_invalid_ciphertext(self):
        # Decrypt a clearly invalid ciphertext; should raise ValueError
        key = os.urandom(32)
        ciphertext = b"bad_data"
        with self.assertRaises(ValueError):
            self.client.crypto.decrypt_file(ciphertext, key)

    def test_verify_tampered_signature(self):
        # Modify signed content and check that signature verification fails
        data = b"Hello, world!"
        signature = self.client.crypto.sign_file(data)
        pubkey = self.client.crypto.get_signing_pubkey()

        tampered = b"Goodbye, world!"
        result = self.client.crypto.verify_file(tampered, signature, pubkey)
        self.assertFalse(result)

    def test_request_list_without_session(self):
        # Should raise ValueError if no session is established with the peer
        with self.assertRaises(ValueError):
            self.client.request_file_list("deadbeef")

    def test_download_file_without_session(self):
        # Should raise ValueError if no session is established when downloading
        with self.assertRaises(ValueError):
            self.client.request_download_file("deadbeef", "secret.txt")

    def test_handle_malformed_download_request(self):
        # Simulate malformed download request data; should not crash
        try:
            self.client._handle_download_request(None, b'INVALID_FORMAT')
            print("[TEST] Malformed download request handled gracefully")
        except Exception as e:
            self.fail(f"Malformed download request raised unexpected exception: {e}")

    def test_invalid_public_key_format(self):
        # Provide an invalid PEM public key string for signature verification
        data = b"sample file data"
        sig = self.client.crypto.sign_file(data)
        invalid_pem = b"invalid PEM key content"
        result = self.client.crypto.verify_file(data, sig, invalid_pem)
        self.assertFalse(result)

if __name__ == "__main__":
    unittest.main()
