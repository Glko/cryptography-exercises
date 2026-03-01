from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime, timezone


def verify_certificate( cert_to_verify :x509.Certificate, ca_cert :x509.Certificate ) -> None:
    
    # Check if the certificate is signed by CA
    
    try:
        ca_cert.public_key().verify(
        cert_to_verify.signature,
        cert_to_verify.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert_to_verify.signature_hash_algorithm
        )
    except InvalidSignature:
        raise InvalidSignature( 'The certificate is not signed by CA' )
    
    # Check if the certificate is valid ( cant check if its revoked )  
    now = datetime.now(timezone.utc)   
    
    if not ( cert_to_verify.not_valid_before_utc <= now <= cert_to_verify.not_valid_after_utc ):
        raise ValueError( 'The certificate is either expired or not yet valid' )
    
    return
      


def main() -> None:
    
    #! TASK 3 cont
    
    with open("C:\\Users\\Jakub\\Desktop\\task_2\\rsa_priv.pem", "rb") as f:
        bob_priv = serialization.load_pem_private_key(f.read(), None) 
    
    with open("C:\\Users\\Jakub\\Desktop\\task_2\\bob_cr.pem", "rb") as f:
        bob_cert = x509.load_pem_x509_certificate(f.read())
        
    bob_pub = bob_priv.public_key()
    bob_cr_pub = bob_cert.public_key()
    
    pub_nums = bob_pub.public_numbers()
    cert_nums = bob_cr_pub.public_numbers()
    
    if ( bob_pub != bob_cr_pub or pub_nums != cert_nums ):
        raise ValueError("The public key in certificate is not bobs")
    
    #! TASK 4
    
    with open("C:\\Users\\Jakub\\Desktop\\task_2\\CA_cert.pem", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    verify_certificate( bob_cert, ca_cert )

if __name__ == '__main__':
    main() 