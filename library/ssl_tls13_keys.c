/*
 *  TLS 1.3 key schedule
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 ( the "License" ); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "common.h"

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)

#include "mbedtls/hkdf.h"
#include "ssl_misc.h"
#include "mbedtls/debug.h"
#include "ssl_tls13_keys.h"
#include "mbedtls/debug.h"

#include <stdint.h>
#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif /* MBEDTLS_PLATFORM_C */

#define MBEDTLS_SSL_TLS1_3_LABEL( name, string )       \
    .name = string,

struct mbedtls_ssl_tls1_3_labels_struct const mbedtls_ssl_tls1_3_labels =
{
    /* This seems to work in C, despite the string literal being one
     * character too long due to the 0-termination. */
    MBEDTLS_SSL_TLS1_3_LABEL_LIST
};

#undef MBEDTLS_SSL_TLS1_3_LABEL

/*
 * This function creates a HkdfLabel structure used in the TLS 1.3 key schedule.
 *
 * The HkdfLabel is specified in RFC 8446 as follows:
 *
 * struct HkdfLabel {
 *   uint16 length;            // Length of expanded key material
 *   opaque label<7..255>;     // Always prefixed by "tls13 "
 *   opaque context<0..255>;   // Usually a communication transcript hash
 * };
 *
 * Parameters:
 * - desired_length: Length of expanded key material
 *                   Even though the standard allows expansion to up to
 *                   2**16 Bytes, TLS 1.3 never uses expansion to more than
 *                   255 Bytes, so we require `desired_length` to be at most
 *                   255. This allows us to save a few Bytes of code by
 *                   hardcoding the writing of the high bytes.
 * - (label, llen): label + label length, without "tls13 " prefix
 *                  The label length MUST be less than or equal to
 *                  MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_LABEL_LEN
 *                  It is the caller's responsibility to ensure this.
 *                  All (label, label length) pairs used in TLS 1.3
 *                  can be obtained via MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN().
 * - (ctx, clen): context + context length
 *                The context length MUST be less than or equal to
 *                MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN
 *                It is the caller's responsibility to ensure this.
 * - dst: Target buffer for HkdfLabel structure,
 *        This MUST be a writable buffer of size
 *        at least SSL_TLS1_3_KEY_SCHEDULE_MAX_HKDF_LABEL_LEN Bytes.
 * - dlen: Pointer at which to store the actual length of
 *         the HkdfLabel structure on success.
 */

static const char tls1_3_label_prefix[6] = "tls13 ";

#define SSL_TLS1_3_KEY_SCHEDULE_HKDF_LABEL_LEN( label_len, context_len ) \
    (   2                  /* expansion length           */ \
      + 1                  /* label length               */ \
      + label_len                                           \
      + 1                  /* context length             */ \
      + context_len )

#define SSL_TLS1_3_KEY_SCHEDULE_MAX_HKDF_LABEL_LEN                      \
    SSL_TLS1_3_KEY_SCHEDULE_HKDF_LABEL_LEN(                             \
                     sizeof(tls1_3_label_prefix) +                      \
                     MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_LABEL_LEN,     \
                     MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN )

static void ssl_tls1_3_hkdf_encode_label(
                            size_t desired_length,
                            const unsigned char *label, size_t llen,
                            const unsigned char *ctx, size_t clen,
                            unsigned char *dst, size_t *dlen )
{
    size_t total_label_len =
        sizeof(tls1_3_label_prefix) + llen;
    size_t total_hkdf_lbl_len =
        SSL_TLS1_3_KEY_SCHEDULE_HKDF_LABEL_LEN( total_label_len, clen );

    unsigned char *p = dst;

    /* Add the size of the expanded key material.
     * We're hardcoding the high byte to 0 here assuming that we never use
     * TLS 1.3 HKDF key expansion to more than 255 Bytes. */
#if MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_EXPANSION_LEN > 255
#error "The implementation of ssl_tls1_3_hkdf_encode_label() is not fit for the \
        value of MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_EXPANSION_LEN"
#endif

    *p++ = 0;
    *p++ = (unsigned char)( ( desired_length >> 0 ) & 0xFF );

    /* Add label incl. prefix */
    *p++ = (unsigned char)( total_label_len & 0xFF );
    memcpy( p, tls1_3_label_prefix, sizeof(tls1_3_label_prefix) );
    p += sizeof(tls1_3_label_prefix);
    memcpy( p, label, llen );
    p += llen;

    /* Add context value */
    *p++ = (unsigned char)( clen & 0xFF );
    if( clen != 0 )
        memcpy( p, ctx, clen );

    /* Return total length to the caller.  */
    *dlen = total_hkdf_lbl_len;
}

int mbedtls_ssl_tls1_3_hkdf_expand_label(
                     mbedtls_md_type_t hash_alg,
                     const unsigned char *secret, size_t slen,
                     const unsigned char *label, size_t llen,
                     const unsigned char *ctx, size_t clen,
                     unsigned char *buf, size_t blen )
{
    const mbedtls_md_info_t *md;
    unsigned char hkdf_label[ SSL_TLS1_3_KEY_SCHEDULE_MAX_HKDF_LABEL_LEN ];
    size_t hkdf_label_len;

    if( llen > MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_LABEL_LEN )
    {
        /* Should never happen since this is an internal
         * function, and we know statically which labels
         * are allowed. */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    if( clen > MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN )
    {
        /* Should not happen, as above. */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    if( blen > MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_EXPANSION_LEN )
    {
        /* Should not happen, as above. */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    md = mbedtls_md_info_from_type( hash_alg );
    if( md == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    ssl_tls1_3_hkdf_encode_label( blen,
                                  label, llen,
                                  ctx, clen,
                                  hkdf_label,
                                  &hkdf_label_len );

    return( mbedtls_hkdf_expand( md,
                                 secret, slen,
                                 hkdf_label, hkdf_label_len,
                                 buf, blen ) );
}

/*
 * The traffic keying material is generated from the following inputs:
 *
 *  - One secret value per sender.
 *  - A purpose value indicating the specific value being generated
 *  - The desired lengths of key and IV.
 *
 * The expansion itself is based on HKDF:
 *
 *   [sender]_write_key = HKDF-Expand-Label( Secret, "key", "", key_length )
 *   [sender]_write_iv  = HKDF-Expand-Label( Secret, "iv" , "", iv_length )
 *
 * [sender] denotes the sending side and the Secret value is provided
 * by the function caller. Note that we generate server and client side
 * keys in a single function call.
 */
int mbedtls_ssl_tls1_3_make_traffic_keys(
                     mbedtls_md_type_t hash_alg,
                     const unsigned char *client_secret,
                     const unsigned char *server_secret,
                     size_t slen, size_t key_len, size_t iv_len,
                     mbedtls_ssl_key_set *keys )
{
    int ret = 0;

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg,
                    client_secret, slen,
                    MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( key ),
                    NULL, 0,
                    keys->client_write_key, key_len );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg,
                    server_secret, slen,
                    MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( key ),
                    NULL, 0,
                    keys->server_write_key, key_len );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg,
                    client_secret, slen,
                    MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( iv ),
                    NULL, 0,
                    keys->client_write_iv, iv_len );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg,
                    server_secret, slen,
                    MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( iv ),
                    NULL, 0,
                    keys->server_write_iv, iv_len );
    if( ret != 0 )
        return( ret );

    keys->key_len = key_len;
    keys->iv_len = iv_len;

    return( 0 );
}

int mbedtls_ssl_tls1_3_derive_secret(
                   mbedtls_md_type_t hash_alg,
                   const unsigned char *secret, size_t slen,
                   const unsigned char *label, size_t llen,
                   const unsigned char *ctx, size_t clen,
                   int ctx_hashed,
                   unsigned char *dstbuf, size_t buflen )
{
    int ret;
    unsigned char hashed_context[ MBEDTLS_MD_MAX_SIZE ];

    const mbedtls_md_info_t *md;
    md = mbedtls_md_info_from_type( hash_alg );
    if( md == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    if( ctx_hashed == MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED )
    {
        ret = mbedtls_md( md, ctx, clen, hashed_context );
        if( ret != 0 )
            return( ret );
        clen = mbedtls_md_get_size( md );
    }
    else
    {
        if( clen > sizeof(hashed_context) )
        {
            /* This should never happen since this function is internal
             * and the code sets `ctx_hashed` correctly.
             * Let's double-check nonetheless to not run at the risk
             * of getting a stack overflow. */
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        memcpy( hashed_context, ctx, clen );
    }

    return( mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg,
                                                  secret, slen,
                                                  label, llen,
                                                  hashed_context, clen,
                                                  dstbuf, buflen ) );
}

int mbedtls_ssl_tls1_3_evolve_secret(
                   mbedtls_md_type_t hash_alg,
                   const unsigned char *secret_old,
                   const unsigned char *input, size_t input_len,
                   unsigned char *secret_new )
{
    int ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    size_t hlen, ilen;
    unsigned char tmp_secret[ MBEDTLS_MD_MAX_SIZE ] = { 0 };
    unsigned char tmp_input [ MBEDTLS_SSL_TLS1_3_MAX_IKM_SIZE ] = { 0 };

    const mbedtls_md_info_t *md;
    md = mbedtls_md_info_from_type( hash_alg );
    if( md == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    hlen = mbedtls_md_get_size( md );

    /* For non-initial runs, call Derive-Secret( ., "derived", "")
     * on the old secret. */
    if( secret_old != NULL )
    {
        MBEDTLS_SSL_PROC_CHK(
            mbedtls_ssl_tls1_3_derive_secret(
                hash_alg,
                secret_old, hlen,
                MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( derived ),
                NULL, 0, /* context */
                MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED,
                tmp_secret, hlen ) );
    }

    if( input != NULL )
    {
        memcpy( tmp_input, input, input_len );
        ilen = input_len;
    }
    else
    {
        ilen = hlen;
    }

    /* HKDF-Extract takes a salt and input key material.
     * The salt is the old secret, and the input key material
     * is the input secret (PSK / ECDHE). */
    MBEDTLS_SSL_PROC_CHK( mbedtls_hkdf_extract( md,
        tmp_secret, hlen,
        tmp_input, ilen,
        secret_new ) );

    ret = 0;

 cleanup:

    mbedtls_platform_zeroize( tmp_secret, sizeof(tmp_secret) );
    mbedtls_platform_zeroize( tmp_input,  sizeof(tmp_input)  );
    return( ret );
}

int mbedtls_ssl_tls1_3_derive_early_secrets(
          mbedtls_md_type_t md_type,
          unsigned char const *early_secret,
          unsigned char const *transcript, size_t transcript_len,
          mbedtls_ssl_tls1_3_early_secrets *derived )
{
    int ret;
    mbedtls_md_info_t const * const md_info = mbedtls_md_info_from_type( md_type );
    size_t const md_size = mbedtls_md_get_size( md_info );

    /* We should never call this function with an unknown hash,
     * but add an assertion anyway. */
    if( md_info == 0 )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    /*
     *            0
     *            |
     *            v
     *  PSK ->  HKDF-Extract = Early Secret
     *            |
     *            +-----> Derive-Secret(., "c e traffic", ClientHello)
     *            |                     = client_early_traffic_secret
     *            |
     *            +-----> Derive-Secret(., "e exp master", ClientHello)
     *            |                     = early_exporter_master_secret
     *            v
     */

    /* Create client_early_traffic_secret */
    ret = mbedtls_ssl_tls1_3_derive_secret( md_type,
                         early_secret, md_size,
                         MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( c_e_traffic ),
                         transcript, transcript_len,
                         MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
                         derived->client_early_traffic_secret,
                         md_size );
    if( ret != 0 )
        return( ret );

    /* Create early exporter */
    ret = mbedtls_ssl_tls1_3_derive_secret( md_type,
                         early_secret, md_size,
                         MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( e_exp_master ),
                         transcript, transcript_len,
                         MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
                         derived->early_exporter_master_secret,
                         md_size );
    if( ret != 0 )
        return( ret );

    return( 0 );
}

int mbedtls_ssl_tls1_3_derive_handshake_secrets(
          mbedtls_md_type_t md_type,
          unsigned char const *handshake_secret,
          unsigned char const *transcript, size_t transcript_len,
          mbedtls_ssl_tls1_3_handshake_secrets *derived )
{
    int ret;
    mbedtls_md_info_t const * const md_info = mbedtls_md_info_from_type( md_type );
    size_t const md_size = mbedtls_md_get_size( md_info );

    /* We should never call this function with an unknown hash,
     * but add an assertion anyway. */
    if( md_info == 0 )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    /*
     *
     * Handshake Secret
     * |
     * +-----> Derive-Secret( ., "c hs traffic",
     * |                     ClientHello...ServerHello )
     * |                     = client_handshake_traffic_secret
     * |
     * +-----> Derive-Secret( ., "s hs traffic",
     * |                     ClientHello...ServerHello )
     * |                     = server_handshake_traffic_secret
     *
     */

    /*
     * Compute client_handshake_traffic_secret with
     * Derive-Secret( ., "c hs traffic", ClientHello...ServerHello )
     */

    ret = mbedtls_ssl_tls1_3_derive_secret( md_type,
             handshake_secret, md_size,
             MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( c_hs_traffic ),
             transcript, transcript_len,
             MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
             derived->client_handshake_traffic_secret,
             md_size );
    if( ret != 0 )
        return( ret );

    /*
     * Compute server_handshake_traffic_secret with
     * Derive-Secret( ., "s hs traffic", ClientHello...ServerHello )
     */

    ret = mbedtls_ssl_tls1_3_derive_secret( md_type,
             handshake_secret, md_size,
             MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( s_hs_traffic ),
             transcript, transcript_len,
             MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
             derived->server_handshake_traffic_secret,
             md_size );
    if( ret != 0 )
        return( ret );

    return( 0 );
}

int mbedtls_ssl_tls1_3_derive_application_secrets(
          mbedtls_md_type_t md_type,
          unsigned char const *application_secret,
          unsigned char const *transcript, size_t transcript_len,
          mbedtls_ssl_tls1_3_application_secrets *derived )
{
    int ret;
    mbedtls_md_info_t const * const md_info = mbedtls_md_info_from_type( md_type );
    size_t const md_size = mbedtls_md_get_size( md_info );

    /* We should never call this function with an unknown hash,
     * but add an assertion anyway. */
    if( md_info == 0 )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    /* Generate {client,server}_application_traffic_secret_0
     *
     * Master Secret
     * |
     * +-----> Derive-Secret( ., "c ap traffic",
     * |                      ClientHello...server Finished )
     * |                      = client_application_traffic_secret_0
     * |
     * +-----> Derive-Secret( ., "s ap traffic",
     * |                      ClientHello...Server Finished )
     * |                      = server_application_traffic_secret_0
     * |
     * +-----> Derive-Secret( ., "exp master",
     * |                      ClientHello...server Finished)
     * |                      = exporter_master_secret
     *
     */

    ret = mbedtls_ssl_tls1_3_derive_secret( md_type,
              application_secret, md_size,
              MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( c_ap_traffic ),
              transcript, transcript_len,
              MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
              derived->client_application_traffic_secret_N,
              md_size );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_ssl_tls1_3_derive_secret( md_type,
              application_secret, md_size,
              MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( s_ap_traffic ),
              transcript, transcript_len,
              MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
              derived->server_application_traffic_secret_N,
              md_size );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_ssl_tls1_3_derive_secret( md_type,
              application_secret, md_size,
              MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( exp_master ),
              transcript, transcript_len,
              MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
              derived->exporter_master_secret,
              md_size );
    if( ret != 0 )
        return( ret );

    return( 0 );
}

#if defined(MBEDTLS_ZERO_RTT)
/* Early Data Key Derivation for TLS 1.3 */
int mbedtls_ssl_tls1_3_generate_early_data_keys(
    mbedtls_ssl_context *ssl,
    mbedtls_ssl_key_set *traffic_keys )
{
    int ret = 0;

    mbedtls_md_type_t md_type;
    mbedtls_md_info_t const *md_info;
    size_t md_size;

    unsigned char transcript[MBEDTLS_MD_MAX_SIZE];
    size_t transcript_len;

    mbedtls_cipher_info_t const *cipher_info;
    size_t keylen, ivlen;

    MBEDTLS_SSL_DEBUG_MSG( 2,
         ( "=> mbedtls_ssl_tls1_3_generate_early_data_keys" ) );

    cipher_info = mbedtls_cipher_info_from_type(
                                  ssl->handshake->ciphersuite_info->cipher );
    keylen = cipher_info->key_bitlen / 8;
    ivlen = cipher_info->iv_size;

    md_type = ssl->handshake->ciphersuite_info->mac;
    md_info = mbedtls_md_info_from_type( md_type );
    md_size = mbedtls_md_get_size( md_info );

    ret = mbedtls_ssl_get_handshake_transcript( ssl, md_type,
                                                transcript, sizeof( transcript ),
                                                &transcript_len );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_get_handshake_transcript", ret );
        return( ret );
    }

    ret = mbedtls_ssl_tls1_3_derive_early_secrets( md_type,
                                   ssl->handshake->tls1_3_master_secrets.early,
                                   transcript, transcript_len,
                                   &ssl->handshake->early_secrets );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_derive_early_secrets", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "client_early_traffic_secret",
                ssl->handshake->early_secrets.client_early_traffic_secret,
                md_size );

#if defined(MBEDTLS_SSL_EXPORT_KEYS)
    if( ssl->f_export_keys != NULL )
    {
        ssl->f_export_keys( ssl->p_export_keys,
                MBEDTLS_SSL_KEY_EXPORT_TLS13_CLIENT_EARLY_SECRET,
                ssl->handshake->early_secrets.client_early_traffic_secret,
                md_size,
                ssl->handshake->randbytes + 32,
                ssl->handshake->randbytes,
                MBEDTLS_SSL_TLS_PRF_NONE /* TODO: FIX! */ );
    }
#endif /* MBEDTLS_SSL_EXPORT_KEYS */

    ret = mbedtls_ssl_tls1_3_make_traffic_keys( md_type,
                      ssl->handshake->early_secrets.client_early_traffic_secret,
                      ssl->handshake->early_secrets.client_early_traffic_secret,
                      md_size, keylen, ivlen, traffic_keys );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_make_traffic_keys", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= mbedtls_ssl_tls1_3_generate_early_data_keys" ) );
    return( ret );
}
#endif /* MBEDTLS_ZERO_RTT */

/* mbedtls_ssl_tls1_3_generate_handshake_keys() generates keys necessary for
 * protecting the handshake messages, as described in Section 7 of TLS 1.3. */
int mbedtls_ssl_tls1_3_generate_handshake_keys(
    mbedtls_ssl_context *ssl,
    mbedtls_ssl_key_set *traffic_keys )
{
    int ret = 0;

    mbedtls_md_type_t md_type;
    mbedtls_md_info_t const *md_info;
    size_t md_size;

    unsigned char transcript[MBEDTLS_MD_MAX_SIZE];
    size_t transcript_len;

    mbedtls_cipher_info_t const *cipher_info;
    size_t keylen, ivlen;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> mbedtls_ssl_tls1_3_generate_handshake_keys" ) );

    cipher_info = mbedtls_cipher_info_from_type(
                                  ssl->handshake->ciphersuite_info->cipher );
    keylen = cipher_info->key_bitlen / 8;
    ivlen = cipher_info->iv_size;

    md_type = ssl->handshake->ciphersuite_info->mac;
    md_info = mbedtls_md_info_from_type( md_type );
    md_size = mbedtls_md_get_size( md_info );

    ret = mbedtls_ssl_get_handshake_transcript( ssl, md_type,
                                                transcript, sizeof( transcript ),
                                                &transcript_len );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_get_handshake_transcript", ret );
        return( ret );
    }

    ret = mbedtls_ssl_tls1_3_derive_handshake_secrets( md_type,
                               ssl->handshake->tls1_3_master_secrets.handshake,
                               transcript, transcript_len,
                               &ssl->handshake->hs_secrets );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_derive_early_secrets", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "Client handshake traffic secret",
                     ssl->handshake->hs_secrets.client_handshake_traffic_secret,
                     md_size );

    MBEDTLS_SSL_DEBUG_BUF( 4, "Server handshake traffic secret",
                     ssl->handshake->hs_secrets.server_handshake_traffic_secret,
                     md_size );

    /*
     * Export client handshake traffic secret
     */
#if defined(MBEDTLS_SSL_EXPORT_KEYS)
    if( ssl->f_export_keys != NULL )
    {
        ssl->f_export_keys( ssl->p_export_keys,
                MBEDTLS_SSL_KEY_EXPORT_TLS13_CLIENT_HANDSHAKE_TRAFFIC_SECRET,
                ssl->handshake->hs_secrets.client_handshake_traffic_secret,
                md_size,
                ssl->handshake->randbytes + 32,
                ssl->handshake->randbytes,
                MBEDTLS_SSL_TLS_PRF_NONE /* TODO: FIX! */ );

        ssl->f_export_keys( ssl->p_export_keys,
                MBEDTLS_SSL_KEY_EXPORT_TLS13_SERVER_HANDSHAKE_TRAFFIC_SECRET,
                ssl->handshake->hs_secrets.server_handshake_traffic_secret,
                md_size,
                ssl->handshake->randbytes + 32,
                ssl->handshake->randbytes,
                MBEDTLS_SSL_TLS_PRF_NONE /* TODO: FIX! */ );
    }
#endif /* MBEDTLS_SSL_EXPORT_KEYS */

    ret = mbedtls_ssl_tls1_3_make_traffic_keys( md_type,
                      ssl->handshake->hs_secrets.client_handshake_traffic_secret,
                      ssl->handshake->hs_secrets.server_handshake_traffic_secret,
                      md_size,
                      keylen, ivlen, traffic_keys );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_make_traffic_keys", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "client_handshake write_key",
                           traffic_keys->client_write_key,
                           traffic_keys->key_len);

    MBEDTLS_SSL_DEBUG_BUF( 4, "server_handshake write_key",
                           traffic_keys->server_write_key,
                           traffic_keys->key_len);

    MBEDTLS_SSL_DEBUG_BUF( 4, "client_handshake write_iv",
                           traffic_keys->client_write_iv,
                           traffic_keys->iv_len);

    MBEDTLS_SSL_DEBUG_BUF( 4, "server_handshake write_iv",
                           traffic_keys->server_write_iv,
                           traffic_keys->iv_len);

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= mbedtls_ssl_tls1_3_generate_handshake_keys" ) );

exit:

    return( ret );
}

/* Generate application traffic keys since any records following a 1-RTT Finished message
 * MUST be encrypted under the application traffic key.
 */
int mbedtls_ssl_tls1_3_generate_application_keys(
                                        mbedtls_ssl_context *ssl,
                                        mbedtls_ssl_key_set *traffic_keys )
{
    int ret = 0;

    /* Address at which to store the application secrets */
    mbedtls_ssl_tls1_3_application_secrets * const app_secrets =
        &ssl->session_negotiate->app_secrets;

    /* Holding the transcript up to and including the ServerFinished */
    unsigned char transcript[MBEDTLS_MD_MAX_SIZE];
    size_t transcript_len;

    /* Variables relating to the hash for the chosen ciphersuite. */
    mbedtls_md_type_t md_type;
    mbedtls_md_info_t const *md_info;
    size_t md_size;

    /* Variables relating to the cipher for the chosen ciphersuite. */
    mbedtls_cipher_info_t const *cipher_info;
    size_t keylen, ivlen;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> derive application traffic keys" ) );

    /* Extract basic information about hash and ciphersuite */

    cipher_info = mbedtls_cipher_info_from_type(
                                  ssl->handshake->ciphersuite_info->cipher );
    keylen = cipher_info->key_bitlen / 8;
    ivlen = cipher_info->iv_size;

    md_type = ssl->handshake->ciphersuite_info->mac;
    md_info = mbedtls_md_info_from_type( md_type );
    md_size = mbedtls_md_get_size( md_info );

    /* Compute current handshake transcript. It's the caller's responsiblity
     * to call this at the right time, that is, after the ServerFinished. */

    ret = mbedtls_ssl_get_handshake_transcript( ssl, md_type,
                                      transcript, sizeof( transcript ),
                                      &transcript_len );
    if( ret != 0 )
        return( ret );

    /* Compute application secrets from master secret and transcript hash. */

    ret = mbedtls_ssl_tls1_3_derive_application_secrets( md_type,
                                   ssl->handshake->tls1_3_master_secrets.app,
                                   transcript, transcript_len,
                                   app_secrets );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1,
                     "mbedtls_ssl_tls1_3_derive_application_secrets", ret );
        return( ret );
    }

    /* Derive first epoch of IV + Key for application traffic. */

    ret = mbedtls_ssl_tls1_3_make_traffic_keys( md_type,
                             app_secrets->client_application_traffic_secret_N,
                             app_secrets->server_application_traffic_secret_N,
                             md_size, keylen, ivlen, traffic_keys );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_make_traffic_keys", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "Client application traffic secret",
                           app_secrets->client_application_traffic_secret_N,
                           md_size );

    MBEDTLS_SSL_DEBUG_BUF( 4, "Server application traffic secret",
                           app_secrets->server_application_traffic_secret_N,
                           md_size );

    /*
     * Export client/server application traffic secret 0
     */
#if defined(MBEDTLS_SSL_EXPORT_KEYS)
    if( ssl->f_export_keys != NULL )
    {
        ssl->f_export_keys( ssl->p_export_keys,
                MBEDTLS_SSL_KEY_EXPORT_TLS13_CLIENT_APPLICATION_TRAFFIC_SECRET,
                app_secrets->client_application_traffic_secret_N, md_size,
                ssl->handshake->randbytes + 32,
                ssl->handshake->randbytes,
                MBEDTLS_SSL_TLS_PRF_NONE /* TODO: FIX! */ );

        ssl->f_export_keys( ssl->p_export_keys,
                MBEDTLS_SSL_KEY_EXPORT_TLS13_SERVER_APPLICATION_TRAFFIC_SECRET,
                app_secrets->server_application_traffic_secret_N, md_size,
                ssl->handshake->randbytes + 32,
                ssl->handshake->randbytes,
                MBEDTLS_SSL_TLS_PRF_NONE /* TODO: FIX! */ );
    }
#endif /* MBEDTLS_SSL_EXPORT_KEYS */

    MBEDTLS_SSL_DEBUG_BUF( 4, "client application_write_key:",
                              traffic_keys->client_write_key, keylen );
    MBEDTLS_SSL_DEBUG_BUF( 4, "server application write key",
                              traffic_keys->server_write_key, keylen );
    MBEDTLS_SSL_DEBUG_BUF( 4, "client application write IV",
                              traffic_keys->client_write_iv, ivlen );
    MBEDTLS_SSL_DEBUG_BUF( 4, "server application write IV",
                              traffic_keys->server_write_iv, ivlen );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= derive application traffic keys" ) );
    return( 0 );
}

#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)
/* Generate resumption_master_secret for use with the ticket exchange.
 *
 * This is not integrated with mbedtls_ssl_tls1_3_derive_application_secrets()
 * because it uses the transcript hash up to and including ClientFinished. */
int mbedtls_ssl_tls1_3_derive_resumption_master_secret(
          mbedtls_md_type_t md_type,
          unsigned char const *application_secret,
          unsigned char const *transcript, size_t transcript_len,
          mbedtls_ssl_tls1_3_application_secrets *derived )
{
    int ret;
    mbedtls_md_info_t const * const md_info = mbedtls_md_info_from_type( md_type );
    size_t const md_size = mbedtls_md_get_size( md_info );

    /* We should never call this function with an unknown hash,
     * but add an assertion anyway. */
    if( md_info == 0 )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    ret = mbedtls_ssl_tls1_3_derive_secret( md_type,
              application_secret, md_size,
              MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( res_master ),
              transcript, transcript_len,
              MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
              derived->resumption_master_secret,
              md_size );

    if( ret != 0 )
        return( ret );

    return( 0 );
}

int mbedtls_ssl_tls1_3_generate_resumption_master_secret(
    mbedtls_ssl_context *ssl )
{
    int ret = 0;

    mbedtls_md_type_t md_type;
    mbedtls_md_info_t const *md_info;
    size_t md_size;

    unsigned char transcript[MBEDTLS_MD_MAX_SIZE];
    size_t transcript_len;

    MBEDTLS_SSL_DEBUG_MSG( 2,
          ( "=> mbedtls_ssl_tls1_3_generate_resumption_master_secret" ) );

    md_type = ssl->handshake->ciphersuite_info->mac;
    md_info = mbedtls_md_info_from_type( md_type );
    md_size = mbedtls_md_get_size( md_info );

    ret = mbedtls_ssl_get_handshake_transcript( ssl, md_type,
                                                transcript, sizeof( transcript ),
                                                &transcript_len );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_ssl_tls1_3_derive_resumption_master_secret( md_type,
                              ssl->handshake->tls1_3_master_secrets.app,
                              transcript, transcript_len,
                              &ssl->session_negotiate->app_secrets );
    if( ret != 0 )
        return( ret );

    MBEDTLS_SSL_DEBUG_BUF( 4, "Resumption master secret",
             ssl->session_negotiate->app_secrets.resumption_master_secret,
             md_size );

    MBEDTLS_SSL_DEBUG_MSG( 2,
          ( "<= mbedtls_ssl_tls1_3_generate_resumption_master_secret" ) );
    return( 0 );
}
#else /* MBEDTLS_SSL_NEW_SESSION_TICKET */
int mbedtls_ssl_tls1_3_generate_resumption_master_secret(
    mbedtls_ssl_context *ssl )
{
    ((void) ssl);
    return( 0 );
}
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */

static int ssl_tls1_3_complete_ephemeral_secret( mbedtls_ssl_context *ssl,
                                                 unsigned char *secret,
                                                 size_t secret_len,
                                                 unsigned char **actual_secret,
                                                 size_t *actual_len )
{
    int ret = 0;

    /*
     * Compute ECDHE secret for second stage of secret evolution.
     */
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDHE_ENABLED)
    if( ssl->handshake->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK ||
        ssl->handshake->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA )
    {
        ret = mbedtls_ecdh_calc_secret(
                   &ssl->handshake->ecdh_ctx,
                   actual_len, secret, secret_len,
                   ssl->conf->f_rng, ssl->conf->p_rng );

        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ecdh_calc_secret", ret );
            return( ret );
        }

        *actual_secret = secret;
    }
    else
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_ECDHE_ENABLED */
    {
        *actual_secret = NULL;
        *actual_len = 0;
    }

    return( 0 );
}

int mbedtls_ssl_tls1_3_key_schedule_stage_handshake(
    mbedtls_ssl_context *ssl )
{
    int ret = 0;
    mbedtls_md_type_t const md_type = ssl->handshake->ciphersuite_info->mac;
#if defined(MBEDTLS_DEBUG_C)
    mbedtls_md_info_t const * const md_info = mbedtls_md_info_from_type( md_type );
    size_t const md_size = mbedtls_md_get_size( md_info );
#endif /* MBEDTLS_DEBUG_C */

    unsigned char *ephemeral;
    size_t ephemeral_len;

    unsigned char ecdhe[66]; /* TODO: Magic constant! */

    /* Finalize calculation of ephemeral input to key schedule, if present. */
    ret = ssl_tls1_3_complete_ephemeral_secret( ssl,
                                                ecdhe, sizeof( ecdhe ),
                                                &ephemeral,
                                                &ephemeral_len );
    if( ret != 0 )
        return( ret );

    /*
     * Compute HandshakeSecret
     */

    ret = mbedtls_ssl_tls1_3_evolve_secret( md_type,
                              ssl->handshake->tls1_3_master_secrets.early,
                              ephemeral, ephemeral_len,
                              ssl->handshake->tls1_3_master_secrets.handshake );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_evolve_secret", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "Handshake secret",
            ssl->handshake->tls1_3_master_secrets.handshake, md_size );

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDHE_ENABLED)
    mbedtls_platform_zeroize( ecdhe, sizeof( ecdhe ) );
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_ECDHE_ENABLED */
    return( 0 );
}

int mbedtls_ssl_tls1_3_key_schedule_stage_application(
    mbedtls_ssl_context *ssl )
{
    int ret = 0;
    mbedtls_md_type_t const md_type = ssl->handshake->ciphersuite_info->mac;
#if defined(MBEDTLS_DEBUG_C)
    mbedtls_md_info_t const * const md_info = mbedtls_md_info_from_type( md_type );
    size_t const md_size = mbedtls_md_get_size( md_info );
#endif /* MBEDTLS_DEBUG_C */

    /*
     * Compute MasterSecret
     */

    ret = mbedtls_ssl_tls1_3_evolve_secret( md_type,
                    ssl->handshake->tls1_3_master_secrets.handshake,
                    NULL, 0,
                    ssl->handshake->tls1_3_master_secrets.app );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_evolve_secret", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "Master secret",
             ssl->handshake->tls1_3_master_secrets.app, md_size );

    return( 0 );
}

static int ssl_tls1_3_calc_finished_core( mbedtls_md_type_t md_type,
                                          unsigned char const *base_key,
                                          unsigned char const *transcript,
                                          unsigned char *dst )
{
    const mbedtls_md_info_t* const md_info = mbedtls_md_info_from_type( md_type );
    size_t const md_size = mbedtls_md_get_size( md_info );
    unsigned char finished_key[MBEDTLS_MD_MAX_SIZE];
    int ret;

    /* We should never call this function with an unknown hash,
     * but add an assertion anyway. */
    if( md_info == 0 )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    /* TLS 1.3 Finished message
     *
     * struct {
     *     opaque verify_data[Hash.length];
     * } Finished;
     *
     * verify_data =
     *     HMAC( finished_key,
     *            Hash( Handshake Context +
     *                  Certificate*      +
     *                  CertificateVerify* )
     *    )
     *
     * finished_key =
     *    HKDF-Expand-Label( BaseKey, "finished", "", Hash.length )
     */

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label(
                                 md_type, base_key, md_size,
                                 MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( finished ),
                                 NULL, 0,
                                 finished_key, md_size );
    if( ret != 0 )
        goto exit;

    ret = mbedtls_md_hmac( md_info, finished_key, md_size, transcript, md_size, dst );
    if( ret != 0 )
        goto exit;

exit:

    mbedtls_platform_zeroize( finished_key, sizeof( finished_key ) );
    return( ret );
}

int mbedtls_ssl_tls1_3_calc_finished( mbedtls_ssl_context* ssl,
                                      unsigned char* dst,
                                      size_t dst_len,
                                      size_t *actual_len,
                                      int from )
{
    int ret;

    unsigned char transcript[MBEDTLS_MD_MAX_SIZE];
    size_t transcript_len;

    unsigned char const *base_key = NULL;

    mbedtls_md_type_t const md_type = ssl->handshake->ciphersuite_info->mac;
    const mbedtls_md_info_t* const md = mbedtls_md_info_from_type( md_type );
    size_t const md_size = mbedtls_md_get_size( md );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> mbedtls_ssl_tls1_3_calc_finished" ) );

    if( dst_len < md_size )
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );

    ret = mbedtls_ssl_get_handshake_transcript( ssl, md_type,
                                                transcript, sizeof( transcript ),
                                                &transcript_len );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_get_handshake_transcript", ret );
        return( ret );
    }
    MBEDTLS_SSL_DEBUG_BUF( 4, "handshake hash", transcript, transcript_len );

    if( from == MBEDTLS_SSL_IS_CLIENT )
        base_key = ssl->handshake->hs_secrets.client_handshake_traffic_secret;
    else
        base_key = ssl->handshake->hs_secrets.server_handshake_traffic_secret;

    ret = ssl_tls1_3_calc_finished_core( md_type, base_key, transcript, dst );
    if( ret != 0 )
        return( ret );
    *actual_len = md_size;

    MBEDTLS_SSL_DEBUG_BUF( 3, "verify_data for finished message", dst, md_size );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= mbedtls_ssl_tls1_3_calc_finished" ) );
    return( 0 );
}

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
/* mbedtls_ssl_tls1_3_create_psk_binder():
 *
 *                0
 *                |
 *                v
 *   PSK ->  HKDF-Extract = Early Secret
 *                |
 *                +------> Derive-Secret( .,
 *                |                      "ext binder" |
 *                |                      "res binder",
 *                |                      "" )
 *                |                     = binder_key
  *               ...
 */

int mbedtls_ssl_tls1_3_create_psk_binder( mbedtls_ssl_context *ssl,
                               const mbedtls_md_type_t md_type,
                               unsigned char const *psk, size_t psk_len,
                               int psk_type,
                               unsigned char const *transcript,
                               unsigned char *result )
{
    int ret = 0;
    unsigned char binder_key[MBEDTLS_MD_MAX_SIZE];
    unsigned char early_secret[MBEDTLS_MD_MAX_SIZE];
    mbedtls_md_info_t const *md_info = mbedtls_md_info_from_type( md_type );
    size_t const md_size = mbedtls_md_get_size( md_info );

#if !defined(MBEDTLS_DEBUG_C)
    ssl = NULL; /* make sure we don't use it except for debug */
    ((void) ssl);
#endif

    /* We should never call this function with an unknown hash,
     * but add an assertion anyway. */
    if( md_info == 0 )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    /*
     *            0
     *            |
     *            v
     *  PSK ->  HKDF-Extract = Early Secret
     *            |
     *            +-----> Derive-Secret(., "ext binder" | "res binder", "")
     *            |                     = binder_key
     *            v
     */

    ret = mbedtls_ssl_tls1_3_evolve_secret( md_type,
                                            NULL,          /* Old secret */
                                            psk, psk_len,  /* Input      */
                                            early_secret );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_evolve_secret", ret );
        goto exit;
    }

    if( psk_type == MBEDTLS_SSL_TLS1_3_PSK_RESUMPTION )
    {
        ret = mbedtls_ssl_tls1_3_derive_secret( md_type,
                            early_secret, md_size,
                            MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( res_binder ),
                            NULL, 0, MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED,
                            binder_key, md_size );
        MBEDTLS_SSL_DEBUG_MSG( 4, ( "Derive Early Secret with 'res binder'" ) );
    }
    else
    {
        ret = mbedtls_ssl_tls1_3_derive_secret( md_type,
                            early_secret, md_size,
                            MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( ext_binder ),
                            NULL, 0, MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED,
                            binder_key, md_size );
        MBEDTLS_SSL_DEBUG_MSG( 4, ( "Derive Early Secret with 'ext binder'" ) );
    }

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_derive_secret", ret );
        goto exit;
    }

    /*
     * The binding_value is computed in the same way as the Finished message
     * but with the BaseKey being the binder_key.
     */

    ret = ssl_tls1_3_calc_finished_core( md_type, binder_key, transcript, result );
    if( ret != 0 )
        goto exit;

    MBEDTLS_SSL_DEBUG_BUF( 3, "psk binder", result, md_size );

exit:

    mbedtls_platform_zeroize( early_secret, sizeof( early_secret ) );
    mbedtls_platform_zeroize( binder_key,   sizeof( binder_key ) );
    return( ret );
}
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

int mbedtls_ssl_tls1_3_key_schedule_stage_early_data(
    mbedtls_ssl_context *ssl )
{
    int ret = 0;
    if( ssl->handshake->ciphersuite_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "cipher suite info not found" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }
    mbedtls_md_type_t const md_type = ssl->handshake->ciphersuite_info->mac;

    ret = mbedtls_ssl_tls1_3_evolve_secret( md_type,
                              NULL,          /* Old secret */
                              ssl->handshake->psk,
                              ssl->handshake->psk_len,
                              ssl->handshake->tls1_3_master_secrets.early );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_evolve_secret", ret );
        return( ret );
    }

    return( 0 );
}

#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */
