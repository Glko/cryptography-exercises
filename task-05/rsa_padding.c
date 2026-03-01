#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <openssl/evp.h>

#define SHA256_SIZE 32

void hexprint( unsigned char *m, char delim, int size )
{
    int i = 0;
    for ( ; i < size -1; i++ )
    {
        printf( "%02hhx%c", m[i], delim );
    }

    printf( "%02hhx", m[i] ); // could be done better 
    printf( "\n" );
}

int create_asn1( X509_SIG **ptr, const unsigned char *hash_data )
{

    if ( !(*ptr = X509_SIG_new() ) ) 
        return -1; // allocation failed;

    X509_ALGOR *alg;
    ASN1_OCTET_STRING *hash;

    ASN1_OBJECT *obj = OBJ_nid2obj( NID_sha256 );
    if ( !obj ) { goto fail; }

    X509_SIG_getm( *ptr, &alg, &hash );
    X509_ALGOR_set0( alg, obj, V_ASN1_NULL, NULL );
    if ( ASN1_OCTET_STRING_set( hash, hash_data, SHA256_SIZE ) <= 0 ) { goto fail; }

    return 0;

fail:    
    X509_SIG_free( *ptr );

    return -1;
}

/*
//if ( !(alg = X509_ALGOR_new() ) ) { goto fail; }
    //if ( !(hash = ASN1_OCTET_STRING_new() ) ) { goto fail; }

if ( alg )
        X509_ALGOR_free( alg );
    if ( hash )
        ASN1_OCTET_STRING_free( hash );*/

int hash_file( const char *path , unsigned char *hash )
{
    const int nbytes = 4096; // 4KB
    int fd = -1, rv = -1;
    ssize_t bytes_read;
    char *buff = NULL;
    EVP_MD_CTX *ctx = NULL;

    if ( ( fd = open( path, O_RDONLY ) ) < 0 ) {
        goto end; }
    
    if ( !( buff = malloc( nbytes ) ) ) {
        goto end; }

    ctx = EVP_MD_CTX_new();
    if ( !ctx ) {
        goto end; }

    if ( EVP_DigestInit_ex( ctx, EVP_sha256(), NULL ) <= 0 ) {
        goto end; }


    while ( ( bytes_read = read( fd, buff, nbytes ) ) > 0 )
    {
        if ( EVP_DigestUpdate( ctx, buff, bytes_read ) <= 0 ) { 
            goto end; }
    }

    if ( bytes_read < 0 ) {
        goto end; }

    if ( EVP_DigestFinal_ex( ctx, hash, NULL ) <= 0 ) {
        goto end; }

    rv = 0;
end:
    if ( fd != -1 )
        close( fd );
    if ( buff )
        free( buff );
    if ( ctx )
        EVP_MD_CTX_free( ctx );
    
    return rv;
}

int create_padding( const char *path , int key_size )
{
    unsigned char hash[ SHA256_SIZE ];
    int rv = -1;
    X509_SIG *signature = NULL;
    unsigned char *rsa_block = malloc( key_size );
    unsigned char *der = NULL;
    
    if ( !rsa_block ) { 
        return rv; }

    if ( hash_file( path, hash ) == -1 ) { 
        goto end; }
    
    if ( create_asn1( &signature, (const unsigned char *)hash ) == -1 ) { 
        goto end; }

    int len = i2d_X509_SIG( signature, NULL );
    
    der = malloc( len );
    if (!der ) {
        goto end; }

    // the second option displayed in my task_2 implementation is let the function allocate the resources

    unsigned char *tmp = der; // since this function moves the pointer to the end of associated data
    i2d_X509_SIG( signature, &tmp ); // we need a tmp pointer ( the data is written to the same mem )
    int padding_size = key_size - len;

    if ( padding_size < 11 ) { 
        goto end; }

    memcpy( rsa_block + padding_size, der, len );

    int i = 0;
    rsa_block[ i++ ] = 0x00;
    rsa_block[ i++ ] = 0x01; 

    for ( ; i < padding_size - 1; i++ )
        rsa_block[ i ] = 0xff;
    
    rsa_block[ i ] = 0x00;

    hexprint( rsa_block, ':', key_size );

    rv = 0;
end:
    free( rsa_block );
    if ( signature )
        X509_SIG_free( signature );
    if ( der )
        free( der );

    return rv;
}



int main()
{
    // key size must be in BYTES
    // feel free to change these parameters as needed;
    int key_size = 256; 
    const char *path = "/path/to/testfile";

    if ( create_padding( path, key_size ) == -1 ) {
        return 1; }

    return 0;
}