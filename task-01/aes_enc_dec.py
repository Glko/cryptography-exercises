import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import padding
from timeit import default_timer as timer

"""
In these tasks, i worked mainly with documentation from this site - https://cryptography.io/en/latest/
as well as some basic googling about python functions working with files

Each task has its encrypt and decrypt file to check that its working ( apart from time checking and chacha, since we need chacha only for time )
also the tasks are denoted by comments in main which starts with #!

Provided paths are for my system, so feel free to change them to use it on your system

In some tasks i havent found a definitive answer, so i voiced my thoughts

"""

def encrypt_aesgcm( key, nonce, file_path_in, file_path_out, ad_data ):

    if len(key) not in (24, 32): # 192, 256 bits
        raise ValueError("The key length must be either 192 or 256 bits")

    """ for this function i opted to use the low level api 
    src: https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.algorithms.AES - the GCM mode
    intead of https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM 
    which i wouldve used for data that im sure can fit in memory
    """
    
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor() # nonce == iv
    
    if ad_data is not None and isinstance(ad_data, str):
        ad_data = ad_data.encode('utf-8')
    
    encryptor.authenticate_additional_data(ad_data)

    with open( file_path_in, "rb") as f_in, open( file_path_out, "wb") as f_out:
       
        # prepend nonce and ad_data

        bytes_write = f_out.write(nonce)
    
        if bytes_write != len(nonce):
            raise Exception("Partial write")
        
        bytes_write = f_out.write(ad_data)
            
        if bytes_write != len(ad_data):
            raise Exception("Partial write")
        
        while ( True ): # go as long as there is data for reading
            
            chunk = f_in.read(4096)
                
            if not chunk:
                break

            ct = encryptor.update(chunk) 
    
            bytes_write = f_out.write(ct)
            
            if bytes_write != len(ct):
                raise Exception("Partial write")
            
            
            # write chunk(4096)
            
        encryptor.finalize()
        
        bytes_write = f_out.write(encryptor.tag)
            
        if bytes_write != len(encryptor.tag):
            raise Exception("Partial write")
        
    return

def decrypt_aesgcm( key, nonce_size, ad_data_size, file_path_in, file_path_out ):

    if len(key) not in (24, 32): # 192, 256 bits
        raise ValueError("The key length must be either 192 or 256 bits")

    with open( file_path_in, "rb") as f_in, open( file_path_out, "wb") as f_out:
        
        nonce = f_in.read(nonce_size)
        ad_data = f_in.read(ad_data_size)
        
        curr_pos = f_in.tell()
        
        f_in.seek(-16, 2)
        
        file_size = f_in.tell() - curr_pos # file_size without nonce, ad_data and tag
        
        tag = f_in.read(16) # the tag produced has 16 bytes by default
        
        f_in.seek(curr_pos)
        
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()

        if ad_data is not None and isinstance(ad_data, str):
            ad_data = ad_data.encode('utf-8')
        
        if ad_data:
            decryptor.authenticate_additional_data(ad_data)
       
        bytes_read = 0 # apart from nonce and ad_data
        
        while bytes_read < file_size : # go as long as there is data for reading

            chunk = f_in.read(min(4096, file_size - bytes_read))
            bytes_read += len(chunk)
                
            if not chunk:
                break

            pt = decryptor.update(chunk)
            
            bytes_write = f_out.write(pt)
            
            if bytes_write != len(pt):
                raise Exception("Partial write")
            
        decryptor.finalize()

    return 

def encrypt_chacha20poly1305( key, nonce, file_path_in, file_path_out, ad_data ):
    if len(key) not in (24, 32): # 192, 256 bits
        raise ValueError("The key length must be either 192 or 256 bits")
    
    chacha = ChaCha20Poly1305(key)
    
    if ad_data is not None and isinstance(ad_data, str):
            ad_data = ad_data.encode('utf-8')
    
    with open( file_path_in, "rb") as f_in, open( file_path_out, "wb") as f_out:
        
        pt = f_in.read()
        
        ct = chacha.encrypt(nonce, pt, ad_data)
        
        bytes_write = f_out.write(ct)
        
        if bytes_write != len(ct):
            raise Exception("Partial write")
    
    return ct

def encrypt_aescbc(key, iv, message):

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(message) + encryptor.finalize()
    
    return ct
    
def decrypt_aescbc(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    pt = decryptor.update(ciphertext) + decryptor.finalize()
    
    return pt
    
def xor_blocks(block1, block2):
    return bytes([b1 ^ b2 for b1, b2 in zip(block1, block2)])
    
def change_meaning(block_before, orig_pt, desired_pt):
    """
    
    P = D ⊕ C[i - 1]
    P' = D ⊕ C'[i - 1]
    where D stands for decrypt(Ciphertext[i]), P for plaintext and C for ciphertext
    
    thus P ⊕ P' = D ⊕ D ⊕ C[i - 1] ⊕ C'[i - 1]
    then C'[i - 1] = C[i - 1] ⊕ P ⊕ P'
    
    """
    
    delta = xor_blocks(orig_pt, desired_pt)
    
    new_ct = xor_blocks(block_before, delta)
    
    return new_ct
    
def main():
    #! TASK 1
    key_size = 256 # bits
    key = os.urandom(key_size // 8)
    nonce_size = 96 # bits
    nonce = os.urandom(nonce_size // 8) # NIST standard - also iv
    file_path_in = "C:\\Users\\Jakub\\Desktop\\task_1\\alice.txt"
    file_path_out = "C:\\Users\\Jakub\\Desktop\\task_1\\alice_enc.txt"
    file_path_dec = "C:\\Users\\Jakub\\Desktop\\task_1\\alice_dec.txt"
    ad_data = "Help me"
    ad_data_size = len(ad_data.encode('utf-8'))
    
    encrypt_aesgcm( key, nonce, file_path_in, file_path_out, ad_data )
    
    #! TASK 2
    
    decrypt_aesgcm( key, nonce_size // 8, ad_data_size, file_path_out, file_path_dec )
    
    #! TASK 3
    
    input_key = b"A key for PV181 task 3" 
    salt = os.urandom(16)
    hkdf = HKDF(algorithm=hashes.SHA3_256(), length=32, salt=salt, info=None)
    key_hkdf = hkdf.derive(input_key)
    nonce_hkdf = os.urandom(nonce_size // 8)
    file_path_out_hkdf = "C:\\Users\\Jakub\\Desktop\\task_1\\alice_enc_hkdf.txt"
    file_path_dec_hkdf = "C:\\Users\\Jakub\\Desktop\\task_1\\alice_dec_hkdf.txt"
    
    encrypt_aesgcm( key_hkdf, nonce_hkdf, file_path_in, file_path_out_hkdf, ad_data )
    decrypt_aesgcm( key_hkdf, nonce_size // 8, ad_data_size, file_path_out_hkdf, file_path_dec_hkdf )

    file_path_out_chacha = "C:\\Users\\Jakub\\Desktop\\task_1\\alice_enc_chacha.txt"
    
    #! TASK 4
    
    # tested the enc and dec process, and it works, reused the key and nonce to better compare the 2 functions - AES GCM and Chacha20poly1305
    encrypt_chacha20poly1305( key, nonce, file_path_in, file_path_out_chacha, ad_data )
    
    #! TASK 5 - time measuring
    
    time_chacha = 0
    time_aesgcm = 0
    iterations = 30000
    file_path_out_time = "C:\\Users\\Jakub\\Desktop\\task_1\\alice_enc_time.txt"
    
    #for _ in range(5):
    for _ in range(iterations):
        start = timer()
        encrypt_aesgcm( key, nonce, file_path_in, file_path_out_time, ad_data )
        end = timer()
        time_aesgcm += end - start
        
    for _ in range(iterations):
        start = timer()
        encrypt_chacha20poly1305( key, nonce, file_path_in, file_path_out_time, ad_data )
        end = timer()
        time_chacha += end - start
    
    avg_gcm = time_aesgcm / iterations
    avg_chacha = time_chacha / iterations
       
    print(f"avg time gcm: {avg_gcm},avg time chacha: {avg_chacha}")
     
    # i ran the iterations 5 times ( in one program run ) - each 30 000 cycles
    """ These are the times accounted for - chacha was faster 2 times, gcm was faster 3 times
    avg time gcm: 0.000959735276561696,avg time chacha: 0.0009401309236690092 - chacha faster
    avg time gcm: 0.0019065245166847793,avg time chacha: 0.002069071826975172 - gcm faster
    avg time gcm: 0.0028902400798358333,avg time chacha: 0.003057717480017648 - gcm faster
    avg time gcm: 0.0038503472698891224,avg time chacha: 0.00397321681677131 - gcm faster
    avg time gcm: 0.004939393293275498,avg time chacha: 0.004932595043423741 - chacha faster
    
    Below i will post times that were achieved by 5 runs of the program 
    
    avg time gcm: 0.00097985817649945,avg time chacha: 0.001027817603010529 - gcm faster
    avg time gcm: 0.0009208319635285686,avg time chacha: 0.0009377491201429317 - gcm faster
    avg time gcm: 0.0009680726498869868,avg time chacha: 0.0009073542434566965 - chacha faster
    avg time gcm: 0.000963734846515581,avg time chacha: 0.0009258680601837114 - chacha faster
    avg time gcm: 0.0009414641633707409,avg time chacha: 0.0009088291133521125 - chacha faster
    
    In this case chacha was faster 3 times
    
    The result seems like its 50/50 for chacha and gcm, however further testing could explain why does this happen ( or it could lean towards one side more )
    
    # side note: i ran the program one last time 3 days later, and chacha was faster at that time
    """
    
    #! Task 6 
    
    padder = padding.PKCS7(128).padder()
    
    
    key_aescbc = os.urandom(32)
    iv_aescbc = os.urandom(16)
    text = b"I would like to withdraw 100000 dollars next week"
    padded_text = padder.update(text) + padder.finalize()
    change_text_block = text[16:32]
    desired_text = b"withdraw 500000 "
    
    ct = encrypt_aescbc(key_aescbc, iv_aescbc, padded_text)
    
    ct_change = ct[:16]
    
    ct_new = change_meaning(ct_change, change_text_block, desired_text) + ct[16:]
    
    pt_new = decrypt_aescbc(key_aescbc, iv_aescbc, ct_new)
    
    print(pt_new)
    
    # The result - 
    # b'\x05\xe4\x85\xc3\x15s\xb7u\x99\x0f\x84\x8bmT\xda\xfe
    # withdraw 500000 dollars next week\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'
    
    """
    As seen above the attack could have severe consequences in money transactions ( more amount withdrawn that wanted ),
    altering order quantities, changing important data in databases ( such as trust factor, or credit score ) 
    and life threatening situations ( increasing medication dosage)
    """
    
if __name__ == '__main__':
    main()