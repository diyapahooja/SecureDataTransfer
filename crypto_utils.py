from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def sign_data(data: bytes, private_pem: bytes) -> bytes:
    priv_key = RSA.import_key(private_pem)
    h = SHA256.new(data)
    signature = pkcs1_15.new(priv_key).sign(h)
    return signature

def verify_signature(data: bytes, signature: bytes, public_pem: bytes) -> bool:
    pub_key = RSA.import_key(public_pem)
    h = SHA256.new(data)
    try:
        pkcs1_15.new(pub_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False