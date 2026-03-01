/*
 * Example: PBKDF2-SHA256 in OpenSSL3
 */
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>

/* Print buffer in HEX with optional separator */
static void hexprint(const unsigned char *d, int n, const char *sep)
{
	int i;

	for (i = 0; i < n; i++)
		printf("%02hhx%s", (const char)d[i], sep);
	printf("\n");
}

typedef struct {
    const char *password;
    size_t password_len;
    const unsigned char *salt;
    size_t salt_len;
    unsigned long iter;
	const unsigned char *expected_dk;
    size_t dk_len; 
} pbkdf2_vector_t;

static int check_vector( pbkdf2_vector_t t_vect, char *alg, char *hash, char flag );

int main(void)
{

	const pbkdf2_vector_t pbkdf2_test_vectors[] = {
    	{ (char *)"password", 8, (unsigned char *)"salt", 4, 1,		
		 (const unsigned char *)"\x0c\x60\xc8\x0f\x96\x1f\x0e\x71\xf3\xa9\xb5\x24\xaf\x60\x12\x06\x2f\xe0\x37\xa6", 20 },
    	{ (char *)"password", 8, (unsigned char *)"salt", 4, 2, 
		 (const unsigned char *)"\xea\x6c\x01\x4d\xc7\x2d\x6f\x8c\xcd\x1e\xd9\x2a\xce\x1d\x41\xf0\xd8\xde\x89\x57", 20 },     
    	{ (char *)"password", 8, (unsigned char *)"salt", 4, 4096,
		 (const unsigned char *)"\x4b\x00\x79\x01\xb7\x65\x48\x9a\xbe\xad\x49\xd9\x26\xf7\x21\xd0\x65\xa4\x29\xc1", 20 },
    	{ (char *)"password", 8, (unsigned char *)"salt", 4, 16777216,
		 (const unsigned char *)"\xee\xfe\x3d\x61\xcd\x4d\xa4\xe4\xe9\x94\x5b\x3d\x6b\xa2\x15\x8c\x26\x34\xe9\x84", 20 },
    	{ (char *)"passwordPASSWORDpassword", 24, (unsigned char *)"saltSALTsaltSALTsaltSALTsaltSALTsalt", 36, 4096,
		 (const unsigned char *)"\x3d\x2e\xec\x4f\xe4\x1c\x84\x9b\x80\xc8\xd8\x36\x62\xc0\xe4\x4a\x8b\x29\x1a\x96\x4c\xf2\xf0\x70\x38", 25 },
    	{ (char *)"pass\0word", 9, (unsigned char *)"sa\0lt", 5, 4096,
		 (const unsigned char *)"\x56\xfa\x6a\xa7\x55\x48\x09\x9d\xcc\x37\xd7\xf0\x34\x25\xe0\xc3", 16 }
	};

	size_t num_of_t_vectors = sizeof(pbkdf2_test_vectors) / sizeof(pbkdf2_vector_t);

	int rv;
	char *alg = "PBKDF2";
	char *task_1 = "SHA1";
	char *task_2 = "SHA256";

	for ( int i = 0; i < num_of_t_vectors; i++ )
	{
		rv = check_vector( pbkdf2_test_vectors[ i ], alg, task_1, 1 ); // flag is only for determining which task im doing
		
		if ( rv == 2 )
		{
			fprintf( stderr, "Task_1: Pbkdf failed to create a key at test vector %d\n", i );
			return 1;
		}
		else if ( rv == 1 )
		{
			fprintf( stderr, "Task_1: Error occured\n" );
			return 1;
		}
		else if ( rv == 3 )
		{
			fprintf(stderr, "Task_1: Test vector num. %d failed!\n", i + 1 );
			return 1;
		}
		printf( "Task_1: Test vector num. %d success!\n", i + 1 );


		printf( "Task_2: Test vector SHA256 num. %d\n", i + 1 );
		rv = check_vector( pbkdf2_test_vectors[ i ], alg, task_2, 0 );

		if ( rv == 2 )
		{
			fprintf( stderr, "Task_2: Pbkdf failed to create a key at test vector %d\n", i + 1 );
			return 1;
		}
		else if ( rv == 1 )
		{
			fprintf( stderr, "Task_2: Error occured\n" );
			return 1;
		}
	}

	return 0;
}

static int check_vector( pbkdf2_vector_t t_vect, char *alg, char *hash, char flag )
{
	EVP_KDF_CTX *ctx;
	EVP_KDF *pbkdf2;
	unsigned char key[32]; // for our purpose it will hold, we could do dynamic alloc, however it is prone to attacks with huge keys

	OSSL_PARAM params[] = {
		OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, (unsigned char *)t_vect.password, t_vect.password_len),
		OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, (unsigned char *)t_vect.salt, t_vect.salt_len),
		OSSL_PARAM_ulong(OSSL_KDF_PARAM_ITER, &t_vect.iter),
		OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, hash, 0),
		OSSL_PARAM_END
	};
	
	//printf("OpenSSL (%s):\n", OpenSSL_version(OPENSSL_VERSION));

	//printf("PBKDF2 (%s-%s) using OpenSSL EVP_KDF provider:\n", alg, hash);

	pbkdf2 = EVP_KDF_fetch(NULL, alg, NULL);
	if (!pbkdf2)
		return 1;

	ctx = EVP_KDF_CTX_new(pbkdf2);
	if (!ctx)
		return 1;

	size_t key_len = flag ? t_vect.dk_len : 32; // 32 as written in task_2 assignment

	if (EVP_KDF_derive(ctx, key, key_len, params ) != 1)
		return 2;

	EVP_KDF_CTX_free(ctx);
	EVP_KDF_free(pbkdf2);

	if ( flag )
	{
		if ( CRYPTO_memcmp( key, t_vect.expected_dk, key_len ) != 0 )
			return 3;
	}
	else
	{
		hexprint(key, key_len, " ");
	}

	return 0;
}
