/*
 *  Message Processing Stack, Layer 3 implementation
 *
 *  Copyright (C) 2006-2018, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
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
 *
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

#include "mbedtls/mps/layer3.h"
#include "../mps_trace.h"
#include "../mps_common.h"

#if defined(MBEDTLS_MPS_SEPARATE_LAYERS) ||     \
    defined(MBEDTLS_MPS_TOP_TRANSLATION_UNIT)

#include "layer3_internal.h"

#if defined(MBEDTLS_MPS_ENABLE_TRACE)
static int mbedtls_mps_trace_id = MBEDTLS_MPS_TRACE_BIT_LAYER_3;
#endif /* MBEDTLS_MPS_ENABLE_TRACE */

#include <stdlib.h>

/*
 * Some debug helpers, captured as macros to keep the code readable.
 */

#if defined(MBEDTLS_MPS_PROTO_TLS)
#define L3_DEBUG_TLS_HS_HEADER( hdr )                                                    \
    do                                                                                   \
    {                                                                                    \
        MBEDTLS_MPS_TRACE_COMMENT( "TLS handshake header" );                            \
        MBEDTLS_MPS_TRACE_COMMENT( "* Type:        %u", (unsigned) (hdr)->type        ); \
        MBEDTLS_MPS_TRACE_COMMENT( "* Length:      %u", (unsigned) (hdr)->len         ); \
    } while( 0 )
#else
#define L3_DEBUG_TLS_HS_HEADER( hdr ) do {} while( 0 )
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
#define L3_DEBUG_DTLS_HS_HEADER( hdr )                                                   \
    do                                                                                   \
    {                                                                                    \
        MBEDTLS_MPS_TRACE_COMMENT( "DTLS handshake header" );                            \
        MBEDTLS_MPS_TRACE_COMMENT( "* Type:        %u", (unsigned) (hdr)->type        ); \
        MBEDTLS_MPS_TRACE_COMMENT( "* Length:      %u", (unsigned) (hdr)->len         ); \
        MBEDTLS_MPS_TRACE_COMMENT( "* Sequence Nr: %u", (unsigned) (hdr)->seq_nr      ); \
        MBEDTLS_MPS_TRACE_COMMENT( "* Frag Offset: %u", (unsigned) (hdr)->frag_offset ); \
        MBEDTLS_MPS_TRACE_COMMENT( "* Frag Length: %u", (unsigned) (hdr)->frag_len    ); \
    } while( 0 )
#else
#define L3_DEBUG_DTLS_HS_HEADER( hdr ) do {} while( 0 )
#endif /* MBEDTLS_MPS_PROTO_DTLS */

#define L3_DEBUG_HS_HEADER( hdr, mode )                                                  \
    do                                                                                   \
    {                                                                                    \
        if( MBEDTLS_MPS_IS_TLS( mode ) )                                                 \
            L3_DEBUG_TLS_HS_HEADER(hdr);                                                 \
        if( MBEDTLS_MPS_IS_DTLS( mode ) )                                                \
            L3_DEBUG_DTLS_HS_HEADER(hdr);                                                \
    } while( 0 )

#define L3_DEBUG_ALERT( alert )                                                          \
    do                                                                                   \
    {                                                                                    \
        MBEDTLS_MPS_TRACE_COMMENT( "Alert, level %u, type %u",                           \
                                   (unsigned) (alert)->level, (alert)->type );           \
    } while( 0 )

#define L3_DEBUG_IN_STATE( l3 )                                                     \
    do                                                                              \
    {                                                                               \
        MBEDTLS_MPS_TRACE_COMMENT( "* External state:  %u",                         \
               (unsigned) l3->io.in.state );                                        \
        MBEDTLS_MPS_TRACE_COMMENT( "* Handshake state: %u",                         \
               (unsigned) l3->io.in.hs.state );                                     \
    } while( 0 )

/*
 * Constants and sizes from the [D]TLS standard
 */

#define MPS_TLS_HS_HDR_SIZE   4 /* The handshake header length in TLS.         */
#define MPS_TLS_ALERT_SIZE    2 /* The length of an Alert message.             */
#define MPS_TLS_ALERT_LEVEL_FATAL   1 /* The 'level' field of a fatal alert.   */
#define MPS_TLS_ALERT_LEVEL_WARNING 2 /* The 'level' field of a warning alert. */
#define MPS_TLS_CCS_SIZE      1 /* The length of a CCS message.                */
#define MPS_TLS_CCS_VALUE     1 /* The expected value of a valid CCS message.  */

#define MPS_DTLS_HS_HDR_SIZE 13 /* The handshake header length in DTLS.        */

/*
 * Init & Free API
 */

int mps_l3_init( mps_l3 *l3, mbedtls_mps_l2 *l2, uint8_t mode )
{
    MBEDTLS_MPS_TRACE_INIT( "mps_l3_init" );
    l3->conf.l2 = l2;

#if !defined(MBEDTLS_MPS_CONF_MODE)
    l3->conf.mode = mode;
#else
    MBEDTLS_MPS_ASSERT_RAW( mode == MBEDTLS_MPS_CONF_MODE, "Bad mode" );
#endif /* !MBEDTLS_MPS_CONF_MODE */

    l3->io.in.state    = MBEDTLS_MPS_MSG_NONE;
    l3->io.in.hs.state = MPS_L3_HS_NONE;
    l3->io.in.raw_in   = NULL;

    l3->io.out.state    = MBEDTLS_MPS_MSG_NONE;
    l3->io.out.hs.state = MPS_L3_HS_NONE;
    l3->io.out.raw_out  = NULL;
    l3->io.out.clearing = 0;

    /* TODO Configure Layer 2
     * - Add allowed record types
     * - Configure constraints for merging, pausing, and empty records. */
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

int mps_l3_free( mps_l3 *l3 )
{
    MBEDTLS_MPS_TRACE_INIT( "mps_l3_free" );
    ((void) l3);
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

/*
 * Reading API
 */

/* TODO: Will we need this at some point? */
/* Check if a message is ready to be processed. */
int UNUSED mps_l3_read_check( mps_l3 *l3 )
{
    return( l3->io.in.state );
}

/* Handles incomplete messages / message headers.
 * In DTLS, this is fatal. In TLS, we need to wait for more data. */
MBEDTLS_MPS_STATIC int l3_incomplete_header( mps_l3 *l3 )
{
    int ret;
    mbedtls_mps_transport_type const mode =
        mbedtls_mps_l3_conf_get_mode( &l3->conf );
    mbedtls_mps_l2* const l2 = mbedtls_mps_l3_get_l2( l3 );

    if( MBEDTLS_MPS_IS_TLS( mode ) )
    {
        MBEDTLS_MPS_TRACE_COMMENT( "Incomplete message header" );
        ret = mps_l2_read_done( l2 );
        if( ret != 0 )
            MBEDTLS_MPS_TRACE_RETURN( ret );
        /* We could return WANT_READ here, because _currently_ no records are
         * buffered by Layer 2, hence progress depends on the availability of
         * the underlying transport. However, this would need to be reconsidered
         * and potentially adapted with any change to Layer 2, so returning
         * MBEDTLS_ERR_MPS_RETRY here is safer. */
        return( MBEDTLS_ERR_MPS_RETRY );
    }
    MBEDTLS_MPS_ELSE_IF_DTLS( mode )
    {
        MBEDTLS_MPS_TRACE( MBEDTLS_MPS_TRACE_TYPE_ERROR,
                           "Incomplete message in DTLS -- abort" );
        return( MBEDTLS_ERR_MPS_INVALID_CONTENT );
    }
}

/* Attempt to receive an incoming message from Layer 2. */
int mps_l3_read( mps_l3 *l3 )
{
    int ret;
    mps_l2_in in;
    mbedtls_mps_transport_type const mode =
        mbedtls_mps_l3_conf_get_mode( &l3->conf );
    mbedtls_mps_l2* const l2 = mbedtls_mps_l3_get_l2( l3 );

    MBEDTLS_MPS_TRACE_INIT( "mps_l3_read" );

    /*
     * Outline:
     * 1  If a message is already open for reading,
     *    do nothing and return its type.
     * 2  If no message is currently open for reading, request
     *    incoming data from the underlying Layer 2 context.
     * 3.1 For all content types different from handshake,
     *     call the type-specific parsing function with the
     *     reader returned from Layer 2.
     * 3.2 For handshake messages, check if an incoming handshake
     *     message is currently being paused.
     * 3.2.1 If no: Parse the TLS/DTLS handshake header from the
     *       incoming data reader, setup a new extended reader
     *       with the total message size, and bind it to the incoming
     *       data reader.
     * 3.2.2 If yes (TLS only!)
     *         Fragmentation of handshake messages across multiple records
     *         do not require handshake headers within the subsequent records.
     *         Hence, we can directly bind the incoming data reader to the
     *         extended reader keeping track of global message bounds.
     */

    /* 1 */
    MBEDTLS_MPS_STATE_VALIDATE_RAW( l3->io.in.state == MBEDTLS_MPS_MSG_NONE,
                                  "mps_l3_read() called in unexpected state." );

    /* 2 */
    /* Request incoming data from Layer 2 context */
    MBEDTLS_MPS_TRACE_COMMENT(  "Check for incoming data on Layer 2" );

    /* TODO: Some compilers complain that `in` could still be
     * uninitialized after the call has succeeded.
     * I can't figure out what, if anything, is wrong here.
     * Need to take a look again at a later point.
     *
     * For now, just force the initialization.
     */
    {
        mps_l2_in l2_in_zero = { .type = 0, .epoch = 0, .rd = NULL };
        in = l2_in_zero;
    }

    ret = mps_l2_read_start( l2, &in );
    if( ret != 0 )
        MBEDTLS_MPS_TRACE_RETURN( ret );

    MBEDTLS_MPS_TRACE_COMMENT(  "Opened incoming datastream" );
    MBEDTLS_MPS_TRACE_COMMENT(  "* Epoch: %u", (unsigned) in.epoch );
    MBEDTLS_MPS_TRACE_COMMENT(  "* Type:  %u", (unsigned) in.type );
    switch( in.type )
    {
        /* Application data */
        case MBEDTLS_MPS_MSG_APP:
            MBEDTLS_MPS_TRACE_COMMENT(  "-> Application data" );
            break;

        /* Alert data */
        case MBEDTLS_MPS_MSG_ALERT:
            MBEDTLS_MPS_TRACE_COMMENT(  "-> Alert message" );

            ret = l3_parse_alert( in.rd, &l3->io.in.alert );
            if( ret == 0 )
                break; /* All good */

            if( ret != MBEDTLS_ERR_MPS_READER_OUT_OF_DATA )
                MBEDTLS_MPS_TRACE_RETURN( ret );

            /* Incomplete alert */
            MBEDTLS_MPS_TRACE_RETURN( l3_incomplete_header( l3 ) );

        /* CCS data */
        case MBEDTLS_MPS_MSG_CCS:
            MBEDTLS_MPS_TRACE_COMMENT(  "-> CCS message" );

            /* We don't need to consider #MBEDTLS_ERR_MPS_READER_OUT_OF_DATA
             * here because the CCS content type does not allow empty
             * records, and hence malicious length-0 records of type CCS
             * will already have been silently skipped over (DTLS) or
             * lead to failure (TLS) by Layer 2. */
            ret = l3_parse_ccs( in.rd );
            if( ret != 0 )
                MBEDTLS_MPS_TRACE_RETURN( ret );
            break;

        case MBEDTLS_MPS_MSG_ACK:
            /* DTLS-1.3-TODO: Implement */
            MBEDTLS_MPS_TRACE_RETURN( MBEDTLS_ERR_MPS_INVALID_CONTENT );

        /* Handshake data */
        case MBEDTLS_MPS_MSG_HS:
            MBEDTLS_MPS_TRACE_COMMENT(  "-> Handshake message" );

            /* Check if a handshake message is currently being paused. */
            if( l3->io.in.hs.state == MPS_L3_HS_NONE )
            {
                MBEDTLS_MPS_TRACE_COMMENT(  "No handshake message is currently processed" );

                /* Attempt to fetch and parse handshake header.
                 * May fail in TLS because of fragmentation. */

                ret = l3_parse_hs_header( mode, in.rd, &l3->io.in.hs );
                if( ret == MBEDTLS_ERR_MPS_READER_OUT_OF_DATA )
                {
                    /* Incomplete handshake header. */
                    MBEDTLS_MPS_TRACE_RETURN( l3_incomplete_header( l3 ) );
                }
                else if( ret != 0 )
                    MBEDTLS_MPS_TRACE_RETURN( ret );

                /* Setup the extended reader keeping track of the
                 * global message bounds. */
                MBEDTLS_MPS_TRACE_COMMENT(
                                   "Setup extended reader for handshake message" );
            }
            else
            {
                /* We should reach this only for paused HS messages in TLS. */
                MBEDTLS_MPS_ASSERT_RAW( MBEDTLS_MPS_IS_TLS( mode ), "" );
                MBEDTLS_MPS_ASSERT_RAW( l3->io.in.hs.state == MPS_L3_HS_PAUSED,
                                        "Invalid Layer 3 handshake state" );
                /* This should never happen, as we don't allow switching
                 * the incoming epoch while pausing the reading of a
                 * handshake message. But double-check nonetheless. */
                MBEDTLS_MPS_ASSERT_RAW( l3->io.in.hs.epoch == in.epoch,
                                        "Unexpected epoch" );
            }

            /* Make changes to internal structures only now
             * that we know that everything went well. */
            l3->io.in.hs.epoch = in.epoch;
            l3->io.in.hs.state = MPS_L3_HS_ACTIVE;
            break;

        default:
            MBEDTLS_MPS_ASSERT_RAW( 0, "Invalid record content type" );
            break;
    }

    l3->io.in.raw_in = in.rd;
    l3->io.in.epoch  = in.epoch;
    l3->io.in.state  = in.type;

    L3_DEBUG_IN_STATE( l3 );
    MBEDTLS_MPS_TRACE_RETURN( l3->io.in.state );
}

MBEDTLS_MPS_STATIC int l3_read_consume_core( mps_l3 *l3,
                                             mps_l3_hs_state new_hs_state )
{
    int res;
    mbedtls_mps_l2* const l2 = mbedtls_mps_l3_get_l2( l3 );

    /* Remove reference to the raw reader borrowed from Layer 2
     * before calling mps_l2_read_done(), which invalidates it. */
    l3->io.in.raw_in = NULL;
    /* Signal that incoming data is fully processed. */
    res = mps_l2_read_done( l2 );
    if( res != 0 )
        return( res );

    /* Reset state */
    if( l3->io.in.state == MBEDTLS_MPS_MSG_HS )
        l3->io.in.hs.state = new_hs_state;
    l3->io.in.state = MBEDTLS_MPS_MSG_NONE;
    return( 0 );
}

/* Mark an incoming message as fully processed. */
int mps_l3_read_consume( mps_l3 *l3 )
{
    MBEDTLS_MPS_TRACE_INIT( "mps_l3_read_consume" );
    MBEDTLS_MPS_TRACE_RETURN( l3_read_consume_core( l3, MPS_L3_HS_NONE ) );
}

#if defined(MBEDTLS_MPS_PROTO_TLS)
/* Pause the processing of an incoming handshake message. */
int mps_l3_read_pause_handshake( mps_l3 *l3 )
{
    MBEDTLS_MPS_TRACE_INIT( "mps_l3_read_pause_handshake" );
    MBEDTLS_MPS_STATE_VALIDATE_RAW(
        l3->io.in.state    == MBEDTLS_MPS_MSG_HS &&
        l3->io.in.hs.state == MPS_L3_HS_ACTIVE,
        "mps_l3_read_pause_handshake() called in unexpected state." );
    MBEDTLS_MPS_TRACE_RETURN( l3_read_consume_core( l3, MPS_L3_HS_PAUSED ) );
}
#endif /* MBEDTLS_MPS_PROTO_TLS */

/*
 * Record content type specific parsing functions.
 */

/* Handshake */

MBEDTLS_MPS_STATIC int l3_parse_hs_header( uint8_t mode, mbedtls_mps_reader *rd,
                                           mps_l3_hs_in_internal *in )
{
    if( MBEDTLS_MPS_IS_TLS( mode ) )
        return( l3_parse_hs_header_tls( rd, in ) );
    MBEDTLS_MPS_ELSE_IF_DTLS( mode )
        return( l3_parse_hs_header_dtls( rd, in ) );
}

#if defined(MBEDTLS_MPS_PROTO_TLS)
MBEDTLS_MPS_STATIC int l3_parse_hs_header_tls( mbedtls_mps_reader *rd,
                                   mps_l3_hs_in_internal *in )
{
    int res;
    unsigned char *tmp;
    mbedtls_mps_size_t const tls_hs_hdr_len = 4;
    mbedtls_mps_size_t const tls_hs_type_offset   = 0;
    mbedtls_mps_size_t const tls_hs_length_offset = 1;
    MBEDTLS_MPS_TRACE_INIT( "l3_parse_hs_header_tls" );

    /* From RFC 5246 (TLS 1.2):
     * enum {
     *     ..., (255)
     * } HandshakeType;
     * struct {
     *     HandshakeType msg_type;
     *     uint24 length;
     *     select (HandshakeType) {
     *       ...
     *     } body;
     * } Handshake; */

    /* This fails for handshake headers crossing record boundaries.
     * It will be caught and handled by the caller. */
    res = mbedtls_mps_reader_get( rd, tls_hs_hdr_len, &tmp, NULL );
    if( res != 0 )
        MBEDTLS_MPS_TRACE_RETURN( res );

    MPS_READ_UINT8_BE ( tmp + tls_hs_type_offset,   &in->type );
    MPS_READ_UINT24_BE( tmp + tls_hs_length_offset, &in->len );

    res = mbedtls_mps_reader_commit( rd );
    if( res != 0 )
        MBEDTLS_MPS_TRACE_RETURN( res );

    L3_DEBUG_TLS_HS_HEADER(in);
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}
#endif /* MBEDTLS_MPS_PROTO_TLS */


#if defined(MBEDTLS_MPS_PROTO_DTLS)
MBEDTLS_MPS_STATIC int l3_parse_hs_header_dtls( mbedtls_mps_reader *rd,
                                    mps_l3_hs_in_internal *in )
{
    int res;
    unsigned char *tmp;
    mbedtls_mps_size_t const dtls_hs_hdr_len         = 13;
    mbedtls_mps_size_t const dtls_hs_type_offset     = 0;
    mbedtls_mps_size_t const dtls_hs_len_offset      = 1;
    mbedtls_mps_size_t const dtls_hs_seq_offset      = 4;
    mbedtls_mps_size_t const dtls_hs_frag_off_offset = 7;
    mbedtls_mps_size_t const dtls_hs_frag_len_offset = 10;
    MBEDTLS_MPS_TRACE_INIT( "parse_hs_header_dtls" );

    /* From RFC 6347 (DTLS 1.2):
     *   struct {
     *     HandshakeType msg_type;
     *     uint24 length;
     *     uint16 message_seq;
     *     uint24 fragment_offset;
     *     uint24 fragment_length;
     *     select (HandshakeType) {
     *       ...
     *     } body;
     *   } Handshake; */

    res = mbedtls_mps_reader_get( rd, dtls_hs_hdr_len, &tmp, NULL );
    if( res != 0 )
        MBEDTLS_MPS_TRACE_RETURN( res );

    MPS_READ_UINT8_BE ( tmp + dtls_hs_type_offset,     &in->type );
    MPS_READ_UINT24_BE( tmp + dtls_hs_len_offset,      &in->len );
    MPS_READ_UINT16_BE( tmp + dtls_hs_seq_offset,      &in->seq_nr );
    MPS_READ_UINT24_BE( tmp + dtls_hs_frag_off_offset, &in->frag_offset );
    MPS_READ_UINT24_BE( tmp + dtls_hs_frag_len_offset, &in->frag_len );

    res = mbedtls_mps_reader_commit( rd );
    if( res != 0 )
        MBEDTLS_MPS_TRACE_RETURN( res );

    /* frag_offset + frag_len cannot overflow within uint32_t
     * since the summands are 24 bit each. */
    if( in->frag_offset + in->frag_len > in->len )
    {
        MBEDTLS_MPS_TRACE_ERROR( "Invalid handshake header: frag_offset (%u) + frag_len (%u) > len (%u)",
               (unsigned)in->frag_offset,
               (unsigned)in->frag_len,
               (unsigned)in->len );
        MBEDTLS_MPS_TRACE_RETURN( MBEDTLS_ERR_MPS_INVALID_CONTENT );
    }

    L3_DEBUG_DTLS_HS_HEADER(in);
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}
#endif /* MBEDTLS_MPS_PROTO_DTLS */

/* Alert */

MBEDTLS_MPS_STATIC int l3_parse_alert( mbedtls_mps_reader *rd,
                           mps_l3_alert_in_internal *alert )
{
    int res;
    unsigned char *tmp;
    MBEDTLS_MPS_TRACE_INIT( "l3_parse_alert" );

    /* From RFC 5246 (TLS 1.2):
     * enum { warning(1), fatal(2), (255) } AlertLevel;
     * enum { close_notify(0), ..., (255) } AlertDescription;
     * struct {
     *     AlertLevel level;
     *     AlertDescription description;
     * } Alert; */

    /* This may fail for an alert at record boundary. Needs to be
     * re-entrant, so no state change before this call. */
    res = mbedtls_mps_reader_get( rd, MPS_TLS_ALERT_SIZE, &tmp, NULL );
    if( res != 0 )
        MBEDTLS_MPS_TRACE_RETURN( res );

    MPS_READ_UINT8_BE( tmp + 0, &alert->level );
    MPS_READ_UINT8_BE( tmp + 1, &alert->type );

    res = mbedtls_mps_reader_commit( rd );
    if( res != 0 )
        MBEDTLS_MPS_TRACE_RETURN( res );

    L3_DEBUG_ALERT(alert);

    if( alert->level != MPS_TLS_ALERT_LEVEL_FATAL &&
        alert->level != MPS_TLS_ALERT_LEVEL_WARNING )
    {
        MBEDTLS_MPS_TRACE_ERROR( "Alert level unknown" );
        MBEDTLS_MPS_TRACE_RETURN( MBEDTLS_ERR_MPS_INVALID_CONTENT );
    }
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

/* CCS */

MBEDTLS_MPS_STATIC int l3_parse_ccs( mbedtls_mps_reader *rd )
{
    int res;
    unsigned char *tmp;
    uint8_t val;
    MBEDTLS_MPS_TRACE_INIT( "l3_parse_ccs" );

    /* From RFC 5246 (TLS 1.2):
     * struct {
     *   enum { change_cipher_spec(1), (255) } type;
     * } ChangeCipherSpec; */

    res = mbedtls_mps_reader_get( rd, MPS_TLS_CCS_SIZE, &tmp, NULL );
    if( res != 0 )
        MBEDTLS_MPS_TRACE_RETURN( res );

    MPS_READ_UINT8_BE( tmp + 0, &val );
    res = mbedtls_mps_reader_commit( rd );
    if( res != 0 )
        MBEDTLS_MPS_TRACE_RETURN( res );

    if( val != MPS_TLS_CCS_VALUE )
    {
        MBEDTLS_MPS_TRACE_ERROR( "Bad CCS value %u", (unsigned) val );
        MBEDTLS_MPS_TRACE_RETURN( MBEDTLS_ERR_MPS_INVALID_CONTENT );
    }
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

/*
 * API for retrieving read-handles for various content types.
 */

int mps_l3_read_handshake( mps_l3 *l3, mps_l3_handshake_in *hs )
{
    mbedtls_mps_transport_type const mode =
        mbedtls_mps_l3_conf_get_mode( &l3->conf );
    MBEDTLS_MPS_TRACE_INIT( "mps_l3_read_handshake" );

    MBEDTLS_MPS_STATE_VALIDATE_RAW(
        l3->io.in.state    == MBEDTLS_MPS_MSG_HS &&
        l3->io.in.hs.state == MPS_L3_HS_ACTIVE,
        "mps_l3_read_handshake() called in unexpected state." );

    hs->epoch  = l3->io.in.epoch;
    hs->len    = l3->io.in.hs.len;
    hs->type   = l3->io.in.hs.type;
    hs->rd     = l3->io.in.raw_in;

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( mode ) )
    {
        hs->seq_nr      = l3->io.in.hs.seq_nr;
        hs->frag_offset = l3->io.in.hs.frag_offset;
        hs->frag_len    = l3->io.in.hs.frag_len;
    }
#endif /* MBEDTLS_MPS_PROTO_DTLS */
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

int mps_l3_read_app( mps_l3 *l3, mps_l3_app_in *app )
{
    MBEDTLS_MPS_TRACE_INIT( "mps_l3_read_app" );
    MBEDTLS_MPS_STATE_VALIDATE_RAW( l3->io.in.state == MBEDTLS_MPS_MSG_APP,
                             "mps_l3_read_app() called in unexpected state." );
    app->epoch = l3->io.in.epoch;
    app->rd = l3->io.in.raw_in;
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

int mps_l3_read_alert( mps_l3 *l3, mps_l3_alert_in *alert )
{
    MBEDTLS_MPS_TRACE_INIT( "mps_l3_read_alert" );
    MBEDTLS_MPS_STATE_VALIDATE_RAW( l3->io.in.state == MBEDTLS_MPS_MSG_ALERT,
                           "mps_l3_read_alert() called in unexpected state." );
    alert->epoch = l3->io.in.epoch;
    alert->type  = l3->io.in.alert.type;
    alert->level = l3->io.in.alert.level;
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

int mps_l3_read_ccs( mps_l3 *l3, mps_l3_ccs_in *ccs )
{
    MBEDTLS_MPS_TRACE_INIT( "mps_l3_read_ccs" );
    MBEDTLS_MPS_STATE_VALIDATE_RAW( l3->io.in.state == MBEDTLS_MPS_MSG_CCS,
                          "mps_l3_read_appccs() called in unexpected state." );
    ccs->epoch = l3->io.in.epoch;
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

/*
 * Writing API
 */

int mps_l3_flush( mps_l3 *l3 )
{
    MBEDTLS_MPS_TRACE_INIT( "mps_l3_flush" );
    l3->io.out.clearing = 1;
    MBEDTLS_MPS_TRACE_RETURN( l3_check_clear( l3 ) );
}

#if defined(MBEDTLS_MPS_PROTO_TLS)
MBEDTLS_MPS_STATIC int l3_check_write_hs_hdr_tls( mps_l3 *l3 )
{
    int res;
    mps_l3_hs_out_internal *hs = &l3->io.out.hs;
    /* Skip HS header on continuations */
    if( hs->hdr == NULL )
        return( 0 );

    MBEDTLS_MPS_ASSERT_RAW( hs->len != MBEDTLS_MPS_SIZE_UNKNOWN,
                            "HS message length unknown" );
    res = l3_write_hs_header_tls( hs );
    if( res != 0 )
        return( res );
    hs->hdr     = NULL;
    hs->hdr_len = 0;
    return( 0 );
}
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
MBEDTLS_MPS_STATIC int l3_check_write_hs_hdr_dtls( mps_l3 *l3 )
{
    int res;
    mps_l3_hs_out_internal *hs = &l3->io.out.hs;
    MBEDTLS_MPS_ASSERT_RAW( hs->hdr      != NULL                     &&
                            hs->len      != MBEDTLS_MPS_SIZE_UNKNOWN &&
                            hs->frag_len != MBEDTLS_MPS_SIZE_UNKNOWN,
                            "Incomplete HS header data" );
    res = l3_write_hs_header_dtls( hs );
    if( res != 0 )
        return( res );
    hs->hdr     = NULL;
    hs->hdr_len = 0;
    return( 0 );
}
#endif /* MBEDTLS_MPS_PROTO_DTLS */

MBEDTLS_MPS_STATIC int l3_check_write_hs_hdr( mps_l3 *l3 )
{
    mbedtls_mps_transport_type const mode =
        mbedtls_mps_l3_conf_get_mode( &l3->conf );
#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( MBEDTLS_MPS_IS_TLS( mode ) )
        return( l3_check_write_hs_hdr_tls( l3 ) );
#endif /* MBEDTLS_MPS_PROTO_TLS */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
    MBEDTLS_MPS_ELSE_IF_DTLS( mode )
        return( l3_check_write_hs_hdr_dtls( l3 ) );
#endif /* MBEDTLS_MPS_PROTO_DTLS */
}

#if !defined(MBEDTLS_MPS_ENABLE_ASSERTIONS)
#define L3_ASSERT_FRAG_BOUNDS(a,b,c) do {} while( 0 )
#else
#define L3_ASSERT_FRAG_BOUNDS(len,frag_offset, frag_len)                    \
    do {                                                                    \
        /* If the total length isn't specified, then                        \
         * then the fragment offset must be 0, and the                      \
         * fragment length must be unspecified, too. */                     \
        MBEDTLS_MPS_ASSERT_RAW( len != MBEDTLS_MPS_SIZE_UNKNOWN ||          \
                               ( frag_offset == 0 &&                        \
                                 frag_len == MBEDTLS_MPS_SIZE_UNKNOWN ),    \
                                "Invalid message bounds" );                 \
                                                                            \
        /* Check that fragment doesn't exceed the total message length. */  \
        if( len      != MBEDTLS_MPS_SIZE_UNKNOWN &&                         \
            frag_len != MBEDTLS_MPS_SIZE_UNKNOWN )                          \
        {                                                                   \
            mbedtls_mps_size_t total_len =                                  \
                (mbedtls_mps_size_t) len;                                   \
            mbedtls_mps_size_t end_of_fragment =                            \
                (mbedtls_mps_size_t)( frag_offset + frag_len );             \
                                                                            \
            MBEDTLS_MPS_ASSERT_RAW( end_of_fragment >= frag_offset &&       \
                                    end_of_fragment <= total_len,           \
                                    "Invalid fragment bounds" );            \
        }                                                                   \
    } while( 0 )
#endif /* MBEDTLS_MPS_ENABLE_ASSERTIONS */

int mps_l3_write_handshake( mps_l3 *l3, mps_l3_handshake_out *out )
{
    int res;
    mbedtls_mps_l2* const l2 = mbedtls_mps_l3_get_l2( l3 );
    mbedtls_mps_transport_type const mode =
        mbedtls_mps_l3_conf_get_mode( &l3->conf );

    MBEDTLS_MPS_TRACE_INIT( "l3_write_handshake" );
    L3_DEBUG_HS_HEADER(out,mode);

#if defined(MBEDTLS_MPS_STATE_VALIDATION)
    if( l3->io.out.hs.state == MPS_L3_HS_PAUSED &&
        ( l3->io.out.hs.epoch != out->epoch ||
          l3->io.out.hs.type  != out->type  ||
          l3->io.out.hs.len   != out->len ) )
    {
        MBEDTLS_MPS_TRACE_ERROR( "Inconsistent parameters on continuation." );
        MBEDTLS_MPS_TRACE_RETURN( MBEDTLS_ERR_MPS_INVALID_ARGS );
    }
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

    res = l3_prepare_write( l3, MBEDTLS_MPS_MSG_HS, out->epoch );
    if( res != 0 )
        MBEDTLS_MPS_TRACE_RETURN( res );

    if( l3->io.out.hs.state == MPS_L3_HS_NONE )
    {
        MBEDTLS_MPS_TRACE_COMMENT(  "No handshake message currently paused" );

        l3->io.out.hs.epoch = out->epoch;
        l3->io.out.hs.len   = out->len;
        l3->io.out.hs.type  = out->type;

        if( MBEDTLS_MPS_IS_TLS( mode ) )
            l3->io.out.hs.hdr_len = MPS_TLS_HS_HDR_SIZE;
#if defined(MBEDTLS_MPS_PROTO_DTLS)
        MBEDTLS_MPS_ELSE_IF_DTLS( mode )
        {
            l3->io.out.hs.hdr_len = MPS_DTLS_HS_HDR_SIZE;
            l3->io.out.hs.seq_nr      = out->seq_nr;
            l3->io.out.hs.frag_len    = out->frag_len;
            l3->io.out.hs.frag_offset = out->frag_offset;
            L3_ASSERT_FRAG_BOUNDS(out->len, out->frag_offset, out->frag_len);
        }
#endif /* MBEDTLS_MPS_PROTO_DTLS */

        MBEDTLS_MPS_TRACE_COMMENT( "Acquire buffer for HS header" );
        res = mbedtls_writer_get( l3->io.out.raw_out,
                                  l3->io.out.hs.hdr_len,
                                  &l3->io.out.hs.hdr, NULL );

        /* If we're at the end of a record and there's not enough space left for
         * a handshake header, abort the write, flush L2, and retry. */
        if( res == MBEDTLS_ERR_WRITER_OUT_OF_DATA )
        {
            MBEDTLS_MPS_TRACE_COMMENT( "Not enough space for HS header, flush" );
            /* Remember that we must flush. */
            l3->io.out.clearing = 1;
            l3->io.out.state = MBEDTLS_MPS_MSG_NONE;
            res = mps_l2_write_done( l2 );
            if( res != 0 )
                MBEDTLS_MPS_TRACE_RETURN( res );

            /* We could return WANT_WRITE here to indicate that progress hinges
             * on the availability of the underlying transport. */
            MBEDTLS_MPS_TRACE_RETURN( MBEDTLS_ERR_MPS_RETRY );
        }
        else if( res != 0 )
            MBEDTLS_MPS_TRACE_RETURN( res );

        /* Commit the header already now, even though it's not yet written.
         * We only commit to writing it at some point. */
        res = mbedtls_writer_commit( l3->io.out.raw_out );
        if( res != 0 )
            MBEDTLS_MPS_TRACE_RETURN( 0 );

        /* Remember commit position so we can calculate the message length later. */
        l3->io.out.hs.hdr_offset = l3->io.out.raw_out->committed;
    }

    l3->io.out.hs.state = MPS_L3_HS_ACTIVE;
    out->wr = l3->io.out.raw_out;
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

int mps_l3_write_app( mps_l3 *l3, mps_l3_app_out *app )
{
    int res;
    mbedtls_mps_epoch_id epoch = app->epoch;
    MBEDTLS_MPS_TRACE_INIT( "l3_write_app: epoch %u", (unsigned) epoch );

    res = l3_prepare_write( l3, MBEDTLS_MPS_MSG_APP, epoch );
    if( res != 0 )
        MBEDTLS_MPS_TRACE_RETURN( res );

    app->wr = l3->io.out.raw_out;
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

int mps_l3_write_alert( mps_l3 *l3, mps_l3_alert_out *alert )
{
    int res;
    unsigned char *tmp;
    mbedtls_mps_epoch_id epoch = alert->epoch;
    mbedtls_mps_l2* const l2 = mbedtls_mps_l3_get_l2( l3 );
    MBEDTLS_MPS_TRACE_INIT( "l3_write_alert: epoch %u", (unsigned) epoch );

    res = l3_prepare_write( l3, MBEDTLS_MPS_MSG_ALERT, epoch );
    if( res != 0 )
        MBEDTLS_MPS_TRACE_RETURN( res );

    res = mbedtls_writer_get( l3->io.out.raw_out, 2, &tmp, NULL );
    if( res == MBEDTLS_ERR_WRITER_OUT_OF_DATA )
    {
        l3->io.out.clearing = 1;
        l3->io.out.state = MBEDTLS_MPS_MSG_NONE;
        res = mps_l2_write_done( l2 );
        if( res != 0 )
            MBEDTLS_MPS_TRACE_RETURN( res );

        /* We could return WANT_WRITE here to indicate that progress hinges
         * on the availability of the underlying transport. */
        MBEDTLS_MPS_TRACE_RETURN( MBEDTLS_ERR_MPS_RETRY );
    }
    else if( res != 0 )
        MBEDTLS_MPS_TRACE_RETURN( res );

    alert->level = &tmp[0];
    alert->type  = &tmp[1];
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

int mps_l3_write_ccs( mps_l3 *l3, mps_l3_ccs_out *ccs )
{
    int res;
    unsigned char *tmp;
    mbedtls_mps_epoch_id epoch = ccs->epoch;
    mbedtls_mps_l2* const l2 = mbedtls_mps_l3_get_l2( l3 );
    MBEDTLS_MPS_TRACE_INIT( "l3_write_ccs: epoch %u", (unsigned) epoch );

    res = l3_prepare_write( l3, MBEDTLS_MPS_MSG_CCS, epoch );
    if( res != 0 )
        MBEDTLS_MPS_TRACE_RETURN( res );

    res = mbedtls_writer_get( l3->io.out.raw_out, 1, &tmp, NULL );
    if( res == MBEDTLS_ERR_WRITER_OUT_OF_DATA )
    {
        l3->io.out.clearing = 1;
        l3->io.out.state = MBEDTLS_MPS_MSG_NONE;
        res = mps_l2_write_done( l2 );
        if( res != 0 )
            MBEDTLS_MPS_TRACE_RETURN( res );

        /* We could return WANT_WRITE here to indicate that progress hinges
         * on the availability of the underlying transport. */
        MBEDTLS_MPS_TRACE_RETURN( MBEDTLS_ERR_MPS_RETRY );
    }
    else if( res != 0 )
        MBEDTLS_MPS_TRACE_RETURN( res );

    *tmp = MPS_TLS_CCS_VALUE;
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

#if defined(MBEDTLS_MPS_PROTO_TLS)
/* Pause the writing of an outgoing handshake message (TLS only). */
int mps_l3_pause_handshake( mps_l3 *l3 )
{
    int res;
    mbedtls_mps_l2* const l2 = mbedtls_mps_l3_get_l2( l3 );
    MBEDTLS_MPS_TRACE_INIT( "mps_l3_pause_handshake" );

    MBEDTLS_MPS_STATE_VALIDATE_RAW(
        l3->io.out.state    == MBEDTLS_MPS_MSG_HS       &&
        l3->io.out.hs.state == MPS_L3_HS_ACTIVE         &&
        l3->io.out.hs.len   != MBEDTLS_MPS_SIZE_UNKNOWN,
        "mps_l3_pause_handshake() called in unexpected state." );

    res = l3_check_write_hs_hdr( l3 );
    if( res != 0 )
        MBEDTLS_MPS_TRACE_RETURN( res );

    /* Remove reference to the raw writer borrowed from Layer 2
     * before calling mps_l2_write_done(), which invalidates it. */
    l3->io.out.raw_out = NULL;
    res = mps_l2_write_done( l2 );
    if( res != 0 )
        MBEDTLS_MPS_TRACE_RETURN( res );

    /* Switch to paused state. */
    l3->io.out.hs.state = MPS_L3_HS_PAUSED;
    l3->io.out.state    = MBEDTLS_MPS_MSG_NONE;
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}
#endif /* MBEDTLS_MPS_PROTO_TLS */

MBEDTLS_MPS_STATIC void l3_autocomplete_hs_length( mps_l3 *l3 )
{
    mbedtls_mps_transport_type const mode =
        mbedtls_mps_l3_conf_get_mode( &l3->conf );

    /* Calculate size of handshake message (fragment) */
    mbedtls_mps_size_t committed = l3->io.out.raw_out->committed -
                                   l3->io.out.hs.hdr_offset;

#if defined(MBEDTLS_MPS_PROTO_TLS)
    MBEDTLS_MPS_IF_TLS( mode )
    {
        if( l3->io.out.hs.len == MBEDTLS_MPS_SIZE_UNKNOWN )
            l3->io.out.hs.len = committed;
    }
#endif /* MBEDTLS_MPS_PROTO_TLS */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
    MBEDTLS_MPS_ELSE_IF_DTLS( mode )
    {
        if( l3->io.out.hs.len == MBEDTLS_MPS_SIZE_UNKNOWN )
            l3->io.out.hs.len = committed;
        if( l3->io.out.hs.frag_len == MBEDTLS_MPS_SIZE_UNKNOWN )
            l3->io.out.hs.frag_len = committed;
    }
#endif /* MBEDTLS_MPS_PROTO_TLS */
}

int mps_l3_dispatch( mps_l3 *l3 )
{
    int res;
    mbedtls_mps_l2* const l2 = mbedtls_mps_l3_get_l2( l3 );
    MBEDTLS_MPS_TRACE_INIT( "mps_l3_dispatch" );

    switch( l3->io.out.state )
    {
        case MBEDTLS_MPS_MSG_HS:
            MBEDTLS_MPS_TRACE_COMMENT( "Dispatch handshake message" );
            MBEDTLS_MPS_ASSERT_RAW( l3->io.out.hs.state == MPS_L3_HS_ACTIVE, "" );

            /* Fill-in length values that user left unspecified */
            l3_autocomplete_hs_length( l3 );

            MBEDTLS_MPS_TRACE_COMMENT( "Write handshake header" );
            res = l3_check_write_hs_hdr( l3 );
            if( res != 0 )
                MBEDTLS_MPS_TRACE_RETURN( res );
            l3->io.out.hs.state = MPS_L3_HS_NONE;
            break;

        case MBEDTLS_MPS_MSG_ALERT:
            MBEDTLS_MPS_TRACE_COMMENT(  "Dispatch alert message" );
            res = mbedtls_writer_commit( l3->io.out.raw_out );
            if( res != 0 )
                MBEDTLS_MPS_TRACE_RETURN( res );
            break;

        case MBEDTLS_MPS_MSG_CCS:
            MBEDTLS_MPS_TRACE_COMMENT(  "Dispatch CCS message" );
            res = mbedtls_writer_commit( l3->io.out.raw_out );
            if( res != 0 )
                MBEDTLS_MPS_TRACE_RETURN( res );
            break;

        case MBEDTLS_MPS_MSG_APP:
            /* The app data is directly written through the writer. */
            MBEDTLS_MPS_TRACE_COMMENT(  "Dispatch application data" );
            break;

        default:
            MBEDTLS_MPS_STATE_VALIDATE_RAW( l3->io.out.state != MBEDTLS_MPS_MSG_NONE,
                "mps_l2_write_done() called in unexpected state." );
            MBEDTLS_MPS_ASSERT_RAW( 0, "Invalid state in mps_l3_write_done()" );
            break;
    }

    /* Remove reference to the raw writer borrowed from Layer 2
     * before calling mps_l2_write_done(), which invalidates it. */
    l3->io.out.raw_out = NULL;
    res = mps_l2_write_done( l2 );
    if( res != 0 )
        MBEDTLS_MPS_TRACE_RETURN( res );

    l3->io.out.state = MBEDTLS_MPS_MSG_NONE;
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

#if defined(MBEDTLS_MPS_PROTO_TLS)
MBEDTLS_MPS_STATIC int l3_write_hs_header_tls( mps_l3_hs_out_internal *hs )

{
    unsigned char *buf = hs->hdr;
    mbedtls_mps_size_t const tls_hs_hdr_len = 4;
    mbedtls_mps_size_t const tls_hs_type_offset   = 0;
    mbedtls_mps_size_t const tls_hs_length_offset = 1;
    MBEDTLS_MPS_ASSERT_RAW( buf != NULL, "Invalid buffer" );
    MBEDTLS_MPS_ASSERT_RAW( hs->hdr_len == tls_hs_hdr_len, "Invalid header" );

    /* From RFC 5246 (TLS 1.2):
     * enum {
     *     ..., (255)
     * } HandshakeType;
     * struct {
     *     HandshakeType msg_type;
     *     uint24 length;
     *     select (HandshakeType) {
     *       ...
     *     } body;
     * } Handshake;
     */
    MPS_WRITE_UINT8_BE ( &hs->type, buf + tls_hs_type_offset   );
    MPS_WRITE_UINT24_BE( &hs->len,  buf + tls_hs_length_offset );

    L3_DEBUG_TLS_HS_HEADER(hs);
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
MBEDTLS_MPS_STATIC int l3_write_hs_header_dtls( mps_l3_hs_out_internal *hs )

{
    unsigned char *buf = hs->hdr;
    mbedtls_mps_size_t const dtls_hs_hdr_len         = 13;
    mbedtls_mps_size_t const dtls_hs_type_offset     = 0;
    mbedtls_mps_size_t const dtls_hs_len_offset      = 1;
    mbedtls_mps_size_t const dtls_hs_seq_offset      = 4;
    mbedtls_mps_size_t const dtls_hs_frag_off_offset = 7;
    mbedtls_mps_size_t const dtls_hs_frag_len_offset = 10;
    MBEDTLS_MPS_ASSERT_RAW( buf != NULL, "Invalid buffer" );
    MBEDTLS_MPS_ASSERT_RAW( hs->hdr_len == dtls_hs_hdr_len, "Invalid header" );

    /* From RFC 6347 (DTLS 1.2):
     *   struct {
     *     HandshakeType msg_type;
     *     uint24 length;
     *     uint16 message_seq;                               // New field
     *     uint24 fragment_offset;                           // New field
     *     uint24 fragment_length;                           // New field
     *     select (HandshakeType) {
     *       ...
     *     } body;
     *   } Handshake; */
    MPS_WRITE_UINT8_BE ( &hs->type,        buf + dtls_hs_type_offset     );
    MPS_WRITE_UINT24_BE( &hs->len,         buf + dtls_hs_len_offset      );
    MPS_WRITE_UINT16_BE( &hs->seq_nr,      buf + dtls_hs_seq_offset      );
    MPS_WRITE_UINT24_BE( &hs->frag_offset, buf + dtls_hs_frag_off_offset );
    MPS_WRITE_UINT24_BE( &hs->frag_len,    buf + dtls_hs_frag_len_offset );

    L3_DEBUG_DTLS_HS_HEADER(hs);
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}
#endif /* MBEDTLS_MPS_PROTO_DTLS */

/*
 * Flush Layer 2 if requested.
 */
MBEDTLS_MPS_STATIC int l3_check_clear( mps_l3 *l3 )
{
    int res;
    mbedtls_mps_l2* const l2 = mbedtls_mps_l3_get_l2( l3 );
    MBEDTLS_MPS_TRACE_INIT( "l3_check_clear" );
    if( l3->io.out.clearing == 0 )
        MBEDTLS_MPS_TRACE_RETURN( 0 );

    res = mps_l2_write_flush( l2 );
    if( res != 0 )
        MBEDTLS_MPS_TRACE_RETURN( res );

    l3->io.out.clearing = 0;
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

/*
 * Request a writer for the respective epoch and content type from Layer 2.
 * This also keeps track of pursuing ongoing but not yet finished flush calls.
 */
MBEDTLS_MPS_STATIC int l3_prepare_write( mps_l3 *l3, mbedtls_mps_msg_type_t port,
                             mbedtls_mps_epoch_id epoch )
{
    int res;
    mps_l2_out out;
    mbedtls_mps_l2* const l2 = mbedtls_mps_l3_get_l2( l3 );
    MBEDTLS_MPS_TRACE_INIT( "l3_prepare_write" );
    MBEDTLS_MPS_TRACE_COMMENT(  "* Type:  %u", (unsigned) port );
    MBEDTLS_MPS_TRACE_COMMENT(  "* Epoch: %u", (unsigned) epoch );

    MBEDTLS_MPS_STATE_VALIDATE_RAW( l3->io.out.state == MBEDTLS_MPS_MSG_NONE,
                      "l3_prepare_write() called in unexpected state." );

#if !defined(MPS_L3_ALLOW_INTERLEAVED_SENDING)
    if( l3->io.out.hs.state == MPS_L3_HS_PAUSED && port != MBEDTLS_MPS_MSG_HS )
    {
        MBEDTLS_MPS_TRACE_ERROR( "Interleaving of outgoing messages is disabled." );
        MBEDTLS_MPS_TRACE_RETURN( MBEDTLS_ERR_MPS_NO_INTERLEAVING );
    }
#endif

    res = l3_check_clear( l3 );
    if( res != 0 )
        MBEDTLS_MPS_TRACE_RETURN( res );

    out.epoch = epoch;
    out.type = port;
    res = mps_l2_write_start( l2, &out );
    if( res != 0 )
        MBEDTLS_MPS_TRACE_RETURN( res );

    l3->io.out.raw_out = out.wr;
    l3->io.out.state   = port;
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

int mps_l3_epoch_add( mps_l3 *ctx,
                      mbedtls_mps_transform_t *transform,
                      mbedtls_mps_epoch_id *epoch )
{
    return( mps_l2_epoch_add( ctx->conf.l2, transform, epoch ) );
}


int mps_l3_epoch_usage( mps_l3 *ctx,
                        mbedtls_mps_epoch_id epoch_id,
                        mbedtls_mps_epoch_usage clear,
                        mbedtls_mps_epoch_usage set )
{
    return( mps_l2_epoch_usage( ctx->conf.l2, epoch_id, clear, set ) );
}

#if defined(MBEDTLS_MPS_PROTO_DTLS)
int mps_l3_force_next_sequence_number( mps_l3 *ctx,
                                       mbedtls_mps_epoch_id epoch_id,
                                       uint64_t ctr )
{
    return( mps_l2_force_next_sequence_number( ctx->conf.l2, epoch_id, ctr ) );
}

int mps_l3_get_last_sequence_number( mps_l3 *ctx,
                                     mbedtls_mps_epoch_id epoch_id,
                                     uint64_t *ctr )
{
    return( mps_l2_get_last_sequence_number( ctx->conf.l2, epoch_id, ctr ) );
}
#endif /* MBEDTLS_MPS_PROTO_DTLS */

#endif /* MBEDTLS_MPS_SEPARATE_LAYERS) ||
          MBEDTLS_MPS_TOP_TRANSLATION_UNIT */
