#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/objects.h>
//#include <openssl/dh.h> -> deprecated
#include <openssl/evp.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>



void hexprint( unsigned char *m, char delim, int size )
{
    int i = 0;
    for ( ; i < size - 1; i++ )
    {
        printf( "%02hhx%c", m[i], delim );
    }

    printf( "%02hhx", m[i] ); // could be done better 
    printf( "\n" );
}

int print_df_params()
{

    int rv = -1;

    //DH *ctx = DH_new();
    EVP_PKEY *params = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id( EVP_PKEY_DH, NULL );
    
    if ( !pctx )
        return rv;
    
    if ( EVP_PKEY_paramgen_init( pctx ) <= 0 ) 
        goto clean;

    if ( EVP_PKEY_CTX_set_dh_nid( pctx , NID_ffdhe2048 ) <= 0 )
        goto clean;
    
    if ( EVP_PKEY_paramgen( pctx, &params ) <= 0 )
        goto clean;

    // we could use i2d_keyparams_bio -> will do der output to BIO *file ( or stdout )
    
    unsigned char *der = NULL;
    int len = i2d_KeyParams( params, &der );

    
    if ( len <= 0 )
    {
        goto clean;
    }

    hexprint( der, ' ', len );
    
    OPENSSL_free( der );
    /* -> deprecated
    // from man pages, the num for generator should be either 2 or 5 and 2048 for key is from the task req
    if ( DH_generate_parameters_ex( ctx, 2048, 5, NULL ) == 0 )
        goto clean;
    */
    rv = 0;

clean:
    if ( pctx )
        EVP_PKEY_CTX_free( pctx );
    if ( params )
        EVP_PKEY_free( params );
    //DH_free( ctx );

    return rv;
} 

int main()
{
    if ( print_df_params() == -1 ) 
        return 1;

    return 0;
}