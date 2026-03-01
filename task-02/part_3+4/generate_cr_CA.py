from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime


def main():
    
    #! TASK 3
    
    #These lines were used to generate and store the private rsa key of CA's csr ( we can derive the public key later )
    """
    key = rsa.generate_private_key( public_exponent=65537, key_size=2048 )
       
    with open("C:\\Users\\Jakub\\Desktop\\task_2\\rsa_priv_CA.pem", "wb") as f:
        f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
    """
    with open("C:\\Users\\Jakub\\Desktop\\task_2\\rsa_priv_CA.pem", "rb") as f:
        file_key = f.read()
        
    # creates csr of CA
        
    priv_key = serialization.load_pem_private_key( file_key, None )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CZ"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Jihomoravsky kraj"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Brno"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "CA_root.com"),
    ])

    # creates self-signed certificate of CA
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        priv_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).sign(priv_key, hashes.SHA256())

    with open("C:\\Users\\Jakub\\Desktop\\task_2\\CA_cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

if __name__ == '__main__':
    main()