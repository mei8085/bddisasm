/*
 * Copyright (c) 2025 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 *
 * Integration test driver for the bddisasm x86 decoder.
 *
 * The test feeds generated/mutated machine code to the decoder under an
 * AddressSanitizer-instrumented build, with the input window restricted to the
 * exact number of bytes handed to the decoder. Every decoded instruction is
 * checked against a set of structural invariants that relate the decoded
 * instruction length to the position/size of all encoded fields and operands.
 *
 * Source layout:
 *   - x86_decode_fuzz.h    : shared declarations
 *   - x86_decode_gen.c     : deterministic corpus generator / mutator
 *   - x86_decode_checks.c  : invariant checking ("oracle")
 *   - x86_decode_fuzz.c    : harness entry point, truncation sweeps, reproducer
 *   - run_x86_decode_tests.py : driver that builds, runs, minimizes & replays
 */
#ifndef X86_DECODE_FUZZ_H
#define X86_DECODE_FUZZ_H

#include "bddisasm.h"

// Maximum number of bytes we ever hand to the decoder.
#define XDF_MAX_LEN         ND_MAX_INSTRUCTION_LENGTH

// Maximum raw instruction length the generator may produce before it is
// clamped down to XDF_MAX_LEN.
#define XDF_GEN_MAX         32

//
// A single test case: the raw bytes plus the decode mode it must be run in.
// `kind` is a short label describing which generator family produced the case.
//
typedef struct _XDF_CASE
{
    unsigned char       Bytes[XDF_GEN_MAX];
    unsigned int        Len;
    unsigned int        DefCode;    // ND_CODE_16 / ND_CODE_32 / ND_CODE_64
    unsigned int        Tag;        // XDF_TAG_* family identifier
} XDF_CASE;

//
// Generator families. These are the "hard" boundaries where decoders most
// often disagree with themselves: prefix soup, VEX/EVEX/XOP/REX2 payloads,
// ModRM/SIB/displacement encodings, immediate payloads, long instructions.
//
#define XDF_TAG_LEGACY      0
#define XDF_TAG_VEX         1
#define XDF_TAG_EVEX        2
#define XDF_TAG_XOP         3
#define XDF_TAG_MODRM       4
#define XDF_TAG_IMMEDIATE   5
#define XDF_TAG_LONG        6
#define XDF_TAG_PREFIX_ONLY 7
#define XDF_TAG_OPCODE38    8
#define XDF_TAG_REX2        9
#define XDF_TAG_MAX         10

//
// Single decoded-byte consumption record, used by layout checks to make sure
// every byte of the decoded instruction is accounted for exactly once.
//
typedef struct _XDF_LAYOUT
{
    unsigned char       Consumed[XDF_MAX_LEN];
    unsigned int        Length;
} XDF_LAYOUT;

//
// Deterministic PRNG (xorshift64*) so failures are byte-for-byte reproducible
// from the recorded seed.
//
typedef struct _XDF_RNG
{
    unsigned long long  State;
} XDF_RNG;

void
XdfRngSeed(
    XDF_RNG *Rng,
    unsigned long long Seed
);

unsigned int
XdfRngNext(
    XDF_RNG *Rng
);

unsigned int
XdfRngRange(
    XDF_RNG *Rng,
    unsigned int Bound
);

//
// Generate the case with the given index, using the given master seed. The
// case is a pure function of (Seed, Index): the same pair always produces the
// same bytes.
//
void
XdfGenerateCase(
    unsigned long long Seed,
    unsigned long long Index,
    XDF_CASE *Case
);

//
// Decode a case with a decode context derived from the case itself.
//
NDSTATUS
XdfDecode(
    const XDF_CASE *Case,
    unsigned int Size,
    INSTRUX *Instrux
);

//
// Decode with an explicit option/vendor/feature combination.
//
NDSTATUS
XdfDecodeEx(
    const XDF_CASE *Case,
    unsigned int Size,
    unsigned int Options,
    unsigned int VendMode,
    unsigned int FeatMode,
    INSTRUX *Instrux
);

//
// Verify, for a *successful* decode, that the decoded instruction is fully
// self-consistent: every encoded field lies inside the instruction window,
// does not overlap another field, no byte is left unaccounted for, operands
// reference in-range registers/memory descriptions, and the encoded payload
// values match the bytes that were actually fed in.
//
// Returns 0 if all invariants hold; otherwise fills `Reason` (if non-NULL)
// with a human readable description and returns -1.
//
int
XdfCheckDecode(
    const INSTRUX *Instrux,
    const unsigned char *Code,
    unsigned int Size,
    const char *Tag,
    char *Reason,
    unsigned int ReasonSize
);

//
// Verify that a *failed* decode did not fabricate a plausible looking
// instruction: no operands, no mnemonic, no metadata, and no length that
// exceeds the input window.
//
int
XdfCheckFailure(
    const INSTRUX *Instrux,
    unsigned int Size,
    const char *Tag,
    char *Reason,
    unsigned int ReasonSize
);

#endif // X86_DECODE_FUZZ_H
