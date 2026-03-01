from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_aesofb( key, iv, file_path_in, file_path_out ):
    
    encryptor = Cipher(algorithms.AES(key), modes.OFB(iv)).encryptor()

    with open( file_path_in, "rb") as f_in, open( file_path_out, "wb") as f_out:
       
        # if i also did decryption i wouldve prepended/appended IV
        
        while ( True ): # go as long as there is data for reading
            
            chunk = f_in.read(4096)
                
            if not chunk:
                break

            ct = encryptor.update(chunk) 
    
            bytes_write = f_out.write(ct)
            
            if bytes_write != len(ct):
                raise Exception("Partial write")
                        
        f_out.write(encryptor.finalize())
        
    return


def main():
    #! TASK 1
    key = bytes.fromhex('757d915fa09ff6785ab9188621e7bd83')
    iv = bytes.fromhex('49d9f29e80f537b30c294cc4fff2afbf')
    file_path_in = "C:\\Users\\Jakub\\Desktop\\task_2\\alice.txt"
    file_path_out = "C:\\Users\\Jakub\\Desktop\\task_2\\alice_enc_aes_ofb.txt"

    encrypt_aesofb( key, iv, file_path_in, file_path_out )

if __name__ == '__main__':
    main()