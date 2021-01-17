/*
 * Copyright (C) EEMBC(R). All Rights Reserved
 * 
 * All EEMBC Benchmark Software are products of EEMBC and are provided under the
 * terms of the EEMBC Benchmark License Agreements. The EEMBC Benchmark Software
 * are proprietary intellectual properties of EEMBC and its Members and is
 * protected under all applicable laws, including all applicable copyright laws.  
 * 
 * If you received this EEMBC Benchmark Software without having a currently
 * effective EEMBC Benchmark License Agreement, you must discontinue use.
 */

#if defined(CRYPTO_MBEDTLS)
#include "mbedtls/config.h"
#include "mbedtls/aes.h"
#include "mbedtls/ccm.h"
#endif /* CRYPTO_MBEDTLS */

 #if defined(CRYPTO_PSA)
#include "psa/crypto.h"

struct psa_encryption_structure
{
    psa_key_attributes_t *attributes;
    psa_key_handle_t key_handle;
};

typedef struct psa_encryption_structure  psa_encryption_structure;
 #endif /* CRYPTO_PSA */

#include "ee_aes.h"

/**
 * Create a context for use with the particular AES mode.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes128_create(
    void              **p_context,  // output: portable context
    aes_cipher_mode_t   mode        // input: AES_ENC or AES_DEC
)
{
#if defined(CRYPTO_PSA)
    psa_encryption_structure *context;
#endif /* CRYPTO_PSA */

    if (mode == AES_ECB)
    {
#if defined(CRYPTO_MBEDTLS)
        *p_context = 
            (mbedtls_aes_context *)th_malloc(sizeof(mbedtls_aes_context));
#endif /* CRYPTO_MBEDTLS */

#if defined(CRYPTO_PSA)
        context = 
            (psa_encryption_structure *)th_malloc(sizeof(psa_encryption_structure));

        context->attributes = th_malloc(sizeof(psa_key_attributes_t));
        memset(context->attributes, 0, sizeof(psa_key_attributes_t));

        psa_set_key_usage_flags( context->attributes,
                                 PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT );
        psa_set_key_algorithm( context->attributes, PSA_ALG_ECB_NO_PADDING );
        psa_set_key_type( context->attributes, PSA_KEY_TYPE_AES );
        psa_set_key_bits( context->attributes, 128 );

        *p_context = context;
#endif /* CRYPTO_PSA */

    }
    else if (mode == AES_CCM)
    {
#if defined(CRYPTO_MBEDTLS)
        *p_context = 
            (mbedtls_ccm_context *)th_malloc(sizeof(mbedtls_ccm_context));
#endif /* CRYPTO_MBEDTLS */

#if defined(CRYPTO_PSA)
        context = 
            (psa_encryption_structure *)th_malloc(sizeof(psa_encryption_structure));

        context->attributes = th_malloc(sizeof(psa_key_attributes_t));
        memset(context->attributes, 0, sizeof(psa_key_attributes_t));

        psa_set_key_usage_flags( context->attributes,
                                 PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT );
        psa_set_key_algorithm( context->attributes, PSA_ALG_CCM );
        psa_set_key_type( context->attributes, PSA_KEY_TYPE_AES );
        psa_set_key_bits( context->attributes, 128 );

        *p_context = context;
#endif /* CRYPTO_PSA */
    }
    else
    {
        th_printf("e-[Unknown mode in th_aes128_create\r\n");
        return EE_STATUS_ERROR;        
    }

    if (*p_context == NULL)
    {
        th_printf("e-[malloc() fail in th_aes128_create\r\n");
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * Initialize the key for an impending operation.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes128_init(
    void                *p_context, // input: portable context
    const unsigned char *p_key,     // input: key
    unsigned int         keylen,    // input: length of key in bytes
    unsigned int         rounds,    // input: number of AES rounds
    aes_function_t       func,      // input: AES_ENC or AES_DEC
    aes_cipher_mode_t    mode       // input: AES_ECB or AES_CCM
)
{
#if defined(CRYPTO_MBEDTLS)
    int                  keybits;
    int                  ret;
    mbedtls_aes_context *p_ecb;
    mbedtls_ccm_context *p_ccm;

    keybits = keylen    * 8;

    if (mode == AES_ECB)
    { 
        p_ecb = (mbedtls_aes_context *)p_context;
        mbedtls_aes_init(p_ecb);
        if (func == AES_ENC)
        {
            ret = mbedtls_aes_setkey_enc(p_ecb, p_key, keybits);
            if (ret != 0)
            {
                th_printf("e-[Failed to set ECB ENC key: -0x%04x]\r\n", -ret);
                return EE_STATUS_ERROR;
            }
        }
        else if (func == AES_DEC)
        {
            ret = mbedtls_aes_setkey_dec(p_ecb, p_key, keybits);
            if (ret != 0)
            {
                th_printf("e-[Failed to set ECB DEC key: -0x%04x]\r\n", -ret);
                return EE_STATUS_ERROR;
            }
        } 
    }
    else if (mode == AES_CCM)
    {
        p_ccm = (mbedtls_ccm_context *)p_context;
        mbedtls_ccm_init(p_ccm);
        ret = mbedtls_ccm_setkey(p_ccm, MBEDTLS_CIPHER_ID_AES, p_key, keybits);
        if (ret != 0)
        {
            th_printf("e-[Failed to set CCM key: -0x%04x]\r\n", -ret);
            return EE_STATUS_ERROR;
        }
    }
    else
    {
        th_printf("e-[Unknown mode in th_aes128_init\r\n");
        return EE_STATUS_ERROR;
    }
#endif /* CRYPTO_MBEDTLS */

#if defined(CRYPTO_PSA)
    psa_status_t status;
    psa_encryption_structure *context = (psa_encryption_structure *) p_context;

    psa_crypto_init( );

    status = psa_import_key( context->attributes, p_key, keylen, &context->key_handle );
    if (status != PSA_SUCCESS)
    {
        th_printf("e-[Failed to set CCM key: -0x%04x]\r\n", -status);
        return EE_STATUS_ERROR;
    }
#endif /* CRYPTO_PSA */

    return EE_STATUS_OK;
}

/**
 * Perform any cleanup required by init, but don't destroy the context.
 *
 * Some implementations of AES perform allocations on init and require a
 * de-init before initializing again, without destroying the context.
 */
void
th_aes128_deinit(
    void              *p_context,   // input: portable context
    aes_cipher_mode_t  mode         // input: AES_ECB or AES_CCM
)
{
#if defined(CRYPTO_MBEDTLS)
    if (mode == AES_CCM) {
        mbedtls_ccm_free((mbedtls_ccm_context *)p_context);
    }
#endif /* CRYPTO_MBEDTLS */

#if defined(CRYPTO_PSA)
    psa_encryption_structure *context = (psa_encryption_structure *) p_context;

    psa_destroy_key( context->key_handle );
#endif /* CRYPTO_PSA */

}

/**
 * Perform an ECB encrypt on a single block of AES_BLOCKSIZE bytes.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes128_ecb_encrypt(
    void                *p_context, // input: portable context
    const unsigned char *p_pt,      // input: plaintext (AES_BLOCKSIZE bytes)
    unsigned char       *p_ct       // output: ciphertext (AES_BLOCKSIZE bytes)
)
{
#if defined(CRYPTO_MBEDTLS)
    mbedtls_aes_encrypt((mbedtls_aes_context *)p_context, p_pt, p_ct);
#endif /* CRYPTO_MBEDTLS */

#if defined(CRYPTO_PSA)
    /*
    psa_status_t status;
    psa_encryption_structure *context = (psa_encryption_structure *) p_context;
    size_t output_length;
    
    status = psa_cipher_encrypt(*context->key_handle,       // key
                                PSA_ALG_ECB_NO_PADDING,    // algorithm
                                p_pt, 16,                  // plaintext
                                p_ct, 16,                  // ciphertext
                                &output_length );          // ciphertext length

    if( status != PSA_SUCCESS )
    {
        return( EE_STATUS_ERROR );
    }
    */
#endif /* CRYPTO_PSA */

    return EE_STATUS_OK;
}

/**
 * Perform an ECB decrypt on a single block of AES_BLOCKSIZE bytes.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes128_ecb_decrypt(
    void                *p_context, // input: portable context
    const unsigned char *p_ct,      // input: ciphertext (AES_BLOCKSIZE bytes)
    unsigned char       *p_pt       // output: plaintext (AES_BLOCKSIZE bytes)
)
{
#if defined(CRYPTO_MBEDTLS)
    mbedtls_aes_decrypt((mbedtls_aes_context *)p_context, p_ct, p_pt);
#endif /* CRYPTO_MBEDTLS */

#if defined(CRYPTO_PSA)
    /*
    psa_status_t status;
    psa_encryption_structure *context = (psa_encryption_structure *) p_context;
    size_t output_length;

    status = psa_cipher_decrypt(*context->key_handle,       // key
                                PSA_ALG_ECB_NO_PADDING,    // algorithm
                                p_ct, 16,                  // ciphertext
                                p_pt, 16,                  // plaintext
                                &output_length );          // plaintext length
    
    if( status != PSA_SUCCESS )
    {
        return( EE_STATUS_ERROR );
    }
    */
#endif /* CRYPTO_PSA */

    return EE_STATUS_OK;
}

/**
 * Perform a CCM encrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes128_ccm_encrypt(
    void                *p_context, // input: portable context
    const unsigned char *p_pt,      // input: plaintext
    unsigned int         ptlen,     // input: length of plaintext in bytes
    unsigned char       *p_ct,      // output: ciphertext
    unsigned char       *p_tag,     // output: tag
    unsigned int         taglen,    // input: tag length in bytes
    unsigned char       *p_iv,      // input: initialization vector
    unsigned int         ivlen      // input: IV length in bytes
)
{
#if defined(CRYPTO_MBEDTLS)
    mbedtls_ccm_context *p_ctx = (mbedtls_ccm_context *)p_context;
    int                  ret;

    ret = mbedtls_ccm_encrypt_and_tag(
        p_ctx,      // CCM context
        ptlen,      // length of the input data in bytes
        p_iv,       // nonce (initialization vector)
        ivlen,      // length of IV in bytes
        NULL,       // additional data
        0,          // length of additional data in bytes
        p_pt,       // buffer holding the input data
        p_ct,       // buffer holding the output data
        p_tag,      // buffer holding the tag
        taglen      // length of the tag to generate in bytes
    ); 

    if (ret != 0)
    {
        th_printf("e-[Failed perform CCM encrypt: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }
#endif /* CRYPTO_MBEDTLS */

#if defined(CRYPTO_PSA)
    psa_status_t status;
    psa_encryption_structure *context = (psa_encryption_structure *) p_context;
    size_t ciphertext_length;

        status = psa_aead_encrypt( context->key_handle,     // key
                                   PSA_ALG_CCM,              // algorithm
                                   p_iv, ivlen,              // nonce
                                   NULL, 0,                  // additional data
                                   p_pt, ptlen,              // plaintext
                                   p_ct, ptlen + taglen,     // ciphertext
                                   &ciphertext_length );     // length of output
/*    if (p_ct > p_tag)
    {
        status = psa_aead_encrypt( context->key_handle,     // key
                                   PSA_ALG_CCM,              // algorithm
                                   p_iv, ivlen,              // nonce
                                   NULL, 0,                  // additional data
                                   p_pt, ptlen,              // plaintext
                                   p_tag, ptlen + taglen,     // ciphertext
                                   &ciphertext_length );     // length of output
    }
    else
    {
        status = psa_aead_encrypt( context->key_handle,     // key
                                   PSA_ALG_CCM,              // algorithm
                                   p_iv, ivlen,              // nonce
                                   NULL, 0,                  // additional data
                                   p_pt, ptlen,              // plaintext
                                   p_ct, ptlen + taglen,     // ciphertext
                                   &ciphertext_length );     // length of output
    }
    */
    if( status != PSA_SUCCESS )
    {
        th_printf("e-[Failed perform CCM encrypt: -0x%04x]\r\n", -status);
        return EE_STATUS_ERROR;
    }
#endif /* CRYPTO_PSA */

    return EE_STATUS_OK;
}

/**
 * Perform a CCM decrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes128_ccm_decrypt(
    void                *p_context, // input: portable context
    const unsigned char *p_ct,      // input: ciphertext
    unsigned int         ctlen,     // input: length of ciphertext in bytes
    unsigned char       *p_pt,      // output: plaintext
    unsigned char       *p_tag,     // input: tag
    unsigned int         taglen,    // input: tag length in bytes
    unsigned char       *p_iv,      // input: initialization vector
    unsigned int         ivlen      // input: IV length in bytes
)
{
#if defined(CRYPTO_MBEDTLS)
    mbedtls_ccm_context *p_ctx = (mbedtls_ccm_context *)p_context;
    int                  ret;

    ret = mbedtls_ccm_auth_decrypt(
        p_ctx,      // CCM context 
        ctlen,      // length of the input data, 
        p_iv,       // nonce (initialization vector)
        ivlen,      // length of IV in bytes
        NULL,       // additional data
        0,          // length of additional data in bytes
        p_ct,       // buffer holding the input data
        p_pt,       // buffer holding the output data
        p_tag,      // buffer holding the tag
        taglen      // length of the tag to generate in bytes
    );

    if (ret != 0)
    {
        th_printf("e-[Failed perform CCM decrypt: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }
#endif /* CRYPTO_MBEDTLS */

#if defined(CRYPTO_PSA)
    psa_status_t status;
    psa_encryption_structure *context = (psa_encryption_structure *) p_context;
    size_t plaintext_length;

    status = psa_aead_decrypt( context->key_handle,   // key
                               PSA_ALG_CCM,            // algorithm
                               p_iv, ivlen,            // nonce
                               NULL, 0,                // additional data
                               p_ct, ctlen,            // ciphertext
                               p_pt, ctlen,            // plaintext
                               &plaintext_length );    // length of output
    if( status != PSA_SUCCESS )
    {
        th_printf("e-[Failed perform CCM decrypt: -0x%04x]\r\n", -status);
        return( EE_STATUS_OK );
    }
#endif /* CRYPTO_PSA */

    return EE_STATUS_OK;
}

/**
 * Clean up the context created.
 * 
 * Indicate the mode that was used for _create()
 */
void
th_aes128_destroy(
    void              *p_context,   // input: portable context
    aes_cipher_mode_t  mode         // input: AES_ECB or AES_CCM
)
{
#if defined(CRYPTO_MBEDTLS)
    if (mode == AES_CCM)
    {
        mbedtls_ccm_free((mbedtls_ccm_context *)p_context);
    }
#endif /* CRYPTO_MBEDTLS */

#if defined(CRYPTO_PSA)
    psa_encryption_structure *context = (psa_encryption_structure *) p_context;

    th_free(context->attributes);

    mbedtls_psa_crypto_free( );
#endif /* CRYPTO_PSA */

    th_free(p_context);
}
