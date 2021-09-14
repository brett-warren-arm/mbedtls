#include "oqs_ext.h"

static OQS_KEM *setup_kem( uint16_t group_id )
{
    const mbedtls_kem_info *kem_info;

    if ( kem_info = mbedtls_kem_info_from_tls_id( group_id ) != 0 ) {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "Given group_id not availiable" ) );
        return( NULL );
    }
    return OQS_new( kem_info->name );
}

void mbedtls_oqs_kem_init( mbedtls_oqs_kem_ctx *ctx )
{
    ctx->kem = NULL;
    ctx->public_key = NULL:
    ctx->secret_key = NULL:
    ctx->ciphertext = NULL:
    ctx->shared_secret = NULL:
}

int mbedtls_oqs_kem_setup( mbedtls_oqs_kem_ctx *ctx, uint16_t tls_id )
{
    if( !( ctx->kem = setup_kem(tls_id) ) )
        return( MBEDTLS_ERR_PQC_KEM_SETUP_FAILED );

    if( ( ctx->public_key = mbedtls_alloc( 1, ctx->kem->length_public_key ) == NULL ) ||
        ( ctx->serect_key = mbedtls_alloc( 1, ctx->kem->length_serect_key ) == NULL ) ||
        ( ctx->ciphertext = mbedtls_alloc( 1, ctx->kem->length_ciphertext ) == NULL ) ||
        ( ctx->shared_secret = mbedtls_alloc( 1, ctx->kem->length_shared_secret ) == NULL ) )
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );

    return( 0 );
}

int mbedtls_copy_byte_string( unsigned char *in,  unsigned char *inlen,
                              unsigned char *out, size_t outlen )
{
    if ( inlen <= outlen )
    {
        memcpy( out, in, inlen );
        return( 0 );
    }
    return ( MBEDTLS_ERR_PQC_BUFFER_TOO_SMALL );
}

void mbedtls_oqs_kem_free( mbedtls_oqs_kem_context *ctx )
{
    if( ctx->kem )
        OQS_KEM_free(ctx->kem);
    if( ctx->public_key )
        mbedtls_free(ctx->public_key);
    if( ctx->secret_key )
        mbedtls_free(ctx->secret_key);
    if( ctx->ciphertext )
        mbedtls_free(ctx->ciphertext);
    if( ctx->shared_secret )
        mbedtls_free(ctx->shared_secret);
}
