
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
import datetime


def main():
    
    #! TASK 3
    
    # feel free to change the path to test it 
    
    with open("C:\\Users\\Jakub\\Desktop\\task_2\\bob.csr", "rb") as f:
        csr = x509.load_pem_x509_csr(f.read())

    with open("C:\\Users\\Jakub\\Desktop\\task_2\\rsa_priv_CA.pem", "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), None)
    
    with open("C:\\Users\\Jakub\\Desktop\\task_2\\CA_cert.pem", "rb") as f:
        ca_cr = x509.load_pem_x509_certificate(f.read())
    
    # Create bobs certificate
    
    bob_cr = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cr.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=90))
    ).sign( priv_key, hashes.SHA256())
    
    with open("C:\\Users\\Jakub\\Desktop\\task_2\\bob_cr.pem", "wb") as f:
        f.write( bob_cr.public_bytes(serialization.Encoding.PEM))

if __name__ == '__main__':
    main()