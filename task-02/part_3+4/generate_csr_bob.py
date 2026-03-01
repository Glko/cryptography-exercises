#from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes


def main():
    
    #! TASK 3
    
    """
    These lines were used to generate and store the private rsa key of Bob's csr ( we can derive the public key later )
    
    key = rsa.generate_private_key( public_exponent=65537, key_size=2048 )
       
    with open("C:\\Users\\Jakub\\Desktop\\task_2\\rsa_priv.pem", "wb") as f:
        f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
    """
    with open("C:\\Users\\Jakub\\Desktop\\task_2\\rsa_priv.pem", "rb") as f:
        file_key = f.read()
        
    priv_key = serialization.load_pem_private_key( file_key, None )
    
    # generate the csr of bob used later in task 3
    
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "CZ"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Jihomoravsky kraj"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Brno"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Bob's company"),
    x509.NameAttribute(NameOID.COMMON_NAME, "bobcompany.com"),
    ])).sign(priv_key, hashes.SHA256())
    
    
    with open("C:\\Users\\Jakub\\Desktop\\task_2\\bob.csr", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

if __name__ == '__main__':
    main()