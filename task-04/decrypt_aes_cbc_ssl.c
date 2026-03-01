#define _POSIX_C_SOURCE 200809L
#include <stdlib.h> //
#include <stdio.h> //
#include <string.h> 
#include <sys/stat.h> //
#include <errno.h> //
#include <ctype.h> //
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define BUFF_SIZE 4096

void safe_print( char *str, int size )
{
    for ( int i = 0; i < size; i++ )
    {
        const char c = (const char)str[ i ];

        if( isprint( c ) || c == '\n' || c == '\t' ) // isprint does not work for newline and tab 
        {
            putchar( c );
        }
    }
    //putchar( '\n'); // dont know if needed
}

void check_file( char *file_path )
{
    struct stat st;
    
    if ( stat( file_path, &st ) < 0 )
    {
        char *mssg = "Failed to check if file exists:";
        
        // think about errno EACCES
        if ( errno == ENOENT )
        {
            mssg = "The provided file does not exists:";
        }
        fprintf( stderr, "%s %s\n", mssg, strerror( errno ) );
        exit( 1 );
    }

    if ( !S_ISREG( st.st_mode ) )
    {
        fprintf( stderr, "The file needs to be regular\n" );
        exit( 1 );
    }
    /* -> Internal allocation for building a ./file_path if the file_path is not absolute, it was overkill
    //char **file = &file_path;
    //char *tmp = NULL;

    if ( strchr( file_path, '/' ) == NULL )
    {
        int len = strlen( file_path ) + 3; // 3 for ./ and \0 delimiter
        tmp = malloc( len ); 

        if ( !tmp )
        {
            fprintf( stderr, "Failed to check if file exists: %s\n", strerror( errno ));
            exit( 1 );
        }

        snprintf( tmp, len, "./%s", file_path );
        
        file = &tmp;
    } -> not needed 

    return file_path; */
}

void aes_cbc_decrypt( const unsigned char *key, const unsigned char *iv, char *file_path )
{
    check_file( file_path );

    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *alg = NULL;
    BIO *source = NULL;
    BIO *filter = NULL;
    BIO *cipher = NULL;
    BIO *head = NULL;
    int rv = 1;

    if ( !(alg = EVP_CIPHER_fetch( NULL, LN_aes_128_cbc, NULL )) )
    {
        fprintf(stderr, "Error fetching algorithm\n");
        goto clean;
    }

    if ( !(source = BIO_new_file( file_path, "rb" )) )
    {
        fprintf(stderr, "Error opening file '%s'\n", file_path);
        goto clean; 
    }

    head = source;
    
    if ( !(filter = BIO_new( BIO_f_base64())) )
    {
        fprintf(stderr, "Error creating base64 filter\n");
        goto clean; 
    }

    head = filter;
    BIO_push( filter, source );

    if (!( cipher = BIO_new( BIO_f_cipher() )) ) 
    {
        fprintf(stderr, "Error creating cipher bio\n");
        goto clean;
    }
    
    head = cipher;
    BIO_push( cipher, filter );

    //char buff_out[ BUFF_SIZE + EVP_MAX_BLOCK_LENGTH ];

    if ( BIO_get_cipher_ctx( cipher, &ctx ) == 0 )
    {
        fprintf(stderr, "Error getting cipher context\n");
        goto clean;
    }

    if ( EVP_DecryptInit_ex2( ctx, alg, key, iv, NULL ) == 0 )
    {
        fprintf( stderr, "Error on initializing the decryption\n" );
        goto clean;
    }

    char buff_in[ BUFF_SIZE ];
    
    int bytes_read; // , bytes_write

    while ( ( bytes_read = BIO_read( cipher, buff_in, BUFF_SIZE ) ) > 0 )
    {
        safe_print( buff_in, bytes_read );
    }

    if ( bytes_read < 0 )
    {
        fprintf( stderr, "Bio_read failed\n" );
        goto clean;
    }

    rv = 0; 

clean:
    if ( rv )
    {
        ERR_print_errors_fp(stderr);
    }

    if ( head )
        BIO_free_all( head );

    EVP_CIPHER_free( alg );


    if ( rv ) exit( 1 );

    // wanted to use EVP for low level encryption, but BIO solves it for me, ill still provide the functions i used below

    //char buff_out[ BUFF_SIZE + EVP_MAX_BLOCK_LENGTH ];
    //EVP_DecryptUpdate( ctx, buff_out, &bytes_write, buff_in, bytes_write );
    //EVP_DecryptFinal( ctx, buff_out, BUFF_SIZE );
    //safe_print( buff_out, bytes_write );
    //EVP_CIPHER_CTX_free( ctx );
}


int main( int argc, char *argv[] )
{
    if ( argc != 2 )
    {
        fprintf( stderr, "There must be exactly one argument" );
        exit( 1 );
    }


    // for the purpose of this exercise the key and iv are set, however change as needed - could be also done with file paths containing the key and iv
    const unsigned char *key = (const unsigned char *)"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
    const unsigned char *iv = (const unsigned char *)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0f";

    aes_cbc_decrypt( key, iv, argv[ 1 ] );

    exit( 0 );
}
