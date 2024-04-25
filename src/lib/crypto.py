from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import binascii


def get_chain_hash(cert_data):
    # Parse the certificate
    cert = x509.load_pem_x509_certificate(cert_data.encode(), default_backend())

    # Get the public key
    public_key = cert.public_key()

    # Get the key in DER format
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Calculate the SHA256 hash
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(public_key_der)
    hash_value = digest.finalize()

    # Convert the hash to hexadecimal string
    return binascii.hexlify(hash_value).decode("utf-8")
