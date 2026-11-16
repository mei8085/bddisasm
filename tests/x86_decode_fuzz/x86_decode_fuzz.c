/*
 * Copyright (c) 2025 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 *
 * x86 decoder integration test harness.
 *
 * Usage:
 *   x86_decode_fuzz run    [--seed N] [--cases N] [--mode 16|32|64|all]
 *                          [--report-dir DIR] [--verbose]
 *   x86_decode_fuzz replay [--case-hex HEX] [--mode 16|32|64]
 *   x86_decode_fuzz regen  --seed N --index N     (prints the case as hex)
 *   x86_decode_fuzz list-ops                      (lists the test case names)
 *   x86_decode_fuzz self-test                     (runs the built-in regression corpus)
 *
 * The harness deliberately restricts the decoder input window to exactly the
 * number of bytes it intends to test (`NdDecodeWithContext(..., Size, ...)`
 * with Size == the exact window). A given case is decoded:
 *
 *   1. at full length, and
 *   2. at every truncation 1..Len-1.
 *
 * For each decode we require:
 *   - success: the checker invariants in x86_decode_checks.c;
 *   - failure: XdfCheckFailure, i.e. no fabricated instruction;
 *   - truncation with Size < Length never succeeds, and a decode that succeeded
 *     with a shorter window must be identical when re-decoded with a window of
 *     exactly Length (window independence);
 *   - the mini decoder (NdDecodeWithContextMini) must agree with the full one
 *     on success/failure and on Length, with and without the
 *     ND_OPTION_SKIP_CACHE_IBYTES fast path, so a cached-bytes bug is caught.
 *
 * Any invariant violation is written to the report directory:
 *   - <tag>-<seed>-<index>-<mode>.bin : the exact bytes;
 *   - <tag>-<seed>-<index>-<mode>.txt : a human readable description;
 *   - <tag>-<seed>-<index>-<mode>.case : a minimal, self-contained reproducer
 *     that `replay --case <file>` reloads and re-checks.
 *
 * Exit status: 0 when every invariant held, 1 on the first reproducible
 * failure after minimization, 2 on a harness/usage error.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "x86_decode_fuzz.h"

#define XDF_REPORT_DIR_DEFAULT  "xdf-report"

// Stop recording after this many distinct failures: enough to triage, small
// enough that a fundamentally broken build does not fill the disk.
#define XDF_MAX_REPORTS         8

// Exact-window decode buffer. The buffer is sized exactly to the window so
// that AddressSanitizer catches any read past the bytes we handed over; but we
// malloc a separate exact-size allocation per window to make even a
// one-byte-past-the-end read a hard error.
typedef struct _XDF_FAILURE
{
    int                 Failed;
    char                Reason[256];
    char                Tag[64];
    unsigned char       Bytes[XDF_GEN_MAX];
    unsigned int        Len;
    unsigned int        Window;
    unsigned int        DefCode;
} XDF_FAILURE;

static const char *
XdfModeName(
    unsigned int DefCode
)
{
    switch (DefCode)
    {
    case ND_CODE_16: return "16";
    case ND_CODE_32: return "32";
    case ND_CODE_64: return "64";
    default:         return "??";
    }
}

static const char *
XdfTagName(
    unsigned int Tag
)
{
    static const char *names[XDF_TAG_MAX] = {
        "legacy", "vex", "evex", "xop", "modrm", "immediate",
        "long", "prefix-only", "opcode38", "rex2",
    };

    return Tag < XDF_TAG_MAX ? names[Tag] : "unknown";
}


static int
XdfParseMode(
    const char *Text
)
{
    if (strcmp(Text, "16") == 0)
    {
        return ND_CODE_16;
    }

    if (strcmp(Text, "32") == 0)
    {
        return ND_CODE_32;
    }

    if (strcmp(Text, "64") == 0)
    {
        return ND_CODE_64;
    }

    return -1;
}


//
// Allocate an exact-size copy of the window. This is what guarantees that
// AddressSanitizer sees an out-of-bounds read if the decoder ever reads past
// the bytes it was told about.
//
static unsigned char *
XdfExactWindow(
    const unsigned char *Bytes,
    unsigned int Size
)
{
    unsigned char *window = (unsigned char *)malloc(Size ? Size : 1);

    if (window == NULL)
    {
        fprintf(stderr, "xdf: out of memory\n");
        exit(2);
    }

    if (Size != 0)
    {
        memcpy(window, Bytes, Size);
    }

    return window;
}


//
// Decode a byte window using an exact-size heap copy. Returns the status and
// fills `Instrux`.
//
static NDSTATUS
XdfDecodeWindow(
    const XDF_CASE *Case,
    unsigned int Size,
    unsigned int Options,
    unsigned int VendMode,
    unsigned int FeatMode,
    INSTRUX *Instrux
)
{
    unsigned char *window = XdfExactWindow(Case->Bytes, Size);
    ND_CONTEXT context;
    NDSTATUS status;

    NdInitContext(&context);
    context.DefCode = Case->DefCode;
    context.DefData = Case->DefCode;
    context.DefStack = Case->DefCode;
    context.VendMode = VendMode;
    context.FeatMode = FeatMode;
    context.Options = Options;

    status = NdDecodeWithContext(Instrux, window, Size, &context);

    free(window);

    return status;
}


//
// Same, but through the mini decoder.
//
static NDSTATUS
XdfDecodeWindowMini(
    const XDF_CASE *Case,
    unsigned int Size,
    unsigned int Options,
    unsigned int VendMode,
    unsigned int FeatMode,
    INSTRUX_MINI *Instrux
)
{
    unsigned char *window = XdfExactWindow(Case->Bytes, Size);
    ND_CONTEXT context;
    NDSTATUS status;

    NdInitContext(&context);
    context.DefCode = Case->DefCode;
    context.DefData = Case->DefCode;
    context.DefStack = Case->DefCode;
    context.VendMode = VendMode;
    context.FeatMode = FeatMode;
    context.Options = Options;

    status = NdDecodeWithContextMini(Instrux, window, Size, &context);

    free(window);

    return status;
}


//
// Check a single (case, window) decode. Returns 0 if everything holds.
//
static int
XdfCheckWindow(
    const XDF_CASE *Case,
    unsigned int Window,
    unsigned int Options,
    unsigned int VendMode,
    unsigned int FeatMode,
    char *Reason,
    unsigned int ReasonSize,
    int *Succeeded
)
{
    INSTRUX instrux;
    NDSTATUS status;

    memset(&instrux, 0, sizeof(instrux));

    status = XdfDecodeWindow(Case, Window, Options, VendMode, FeatMode, &instrux);

    *Succeeded = ND_SUCCESS(status) ? 1 : 0;

    if (ND_SUCCESS(status))
    {
        if (XdfCheckDecode(&instrux, Case->Bytes, Window, "decode", Reason, ReasonSize) != 0)
        {
            return -1;
        }

        // A successful decode at this window must be reproducible with a
        // window of exactly the decoded length: the decoder's result may not
        // depend on bytes after the instruction.
        if (instrux.Length != Window)
        {
            INSTRUX exact;
            NDSTATUS exactStatus;

            memset(&exact, 0, sizeof(exact));
            exactStatus = XdfDecodeWindow(Case, instrux.Length, Options, VendMode, FeatMode, &exact);

            if (!ND_SUCCESS(exactStatus))
            {
                snprintf(Reason, ReasonSize,
                         "window-independence: decode at length %u failed (%08x) after succeeding at %u",
                         instrux.Length, exactStatus, Window);
                return -1;
            }

            if (exact.Length != instrux.Length ||
                exact.Instruction != instrux.Instruction
#ifndef BDDISASM_NO_MNEMONIC
                || exact.Mnemonic != instrux.Mnemonic
#endif // !BDDISASM_NO_MNEMONIC
                )
            {
                snprintf(Reason, ReasonSize,
                         "window-independence: length/instruction differs between window %u (len %u) and %u (len %u)",
                         Window, instrux.Length, instrux.Length, exact.Length);
                return -1;
            }
        }
    }
    else
    {
        if (XdfCheckFailure(&instrux, Window, "failure", Reason, ReasonSize) != 0)
        {
            return -1;
        }
    }

    return 0;
}


static int
XdfCheckMini(
    const XDF_CASE *Case,
    unsigned int Window,
    unsigned int Options,
    unsigned int VendMode,
    unsigned int FeatMode,
    char *Reason,
    unsigned int ReasonSize
)
{
    INSTRUX full;
    INSTRUX_MINI mini;
    NDSTATUS fullStatus;
    NDSTATUS miniStatus;

    memset(&full, 0, sizeof(full));
    memset(&mini, 0, sizeof(mini));

    fullStatus = XdfDecodeWindow(Case, Window, Options, VendMode, FeatMode, &full);
    miniStatus = XdfDecodeWindowMini(Case, Window, Options, VendMode, FeatMode, &mini);

    if ((ND_SUCCESS(fullStatus) ? 1 : 0) != (ND_SUCCESS(miniStatus) ? 1 : 0))
    {
        snprintf(Reason, ReasonSize,
                 "mini decoder disagrees on success: full=%08x mini=%08x (window %u, options %u)",
                 fullStatus, miniStatus, Window, Options);
        return -1;
    }

    if (ND_SUCCESS(fullStatus) && full.Length != mini.Length)
    {
        snprintf(Reason, ReasonSize,
                 "mini decoder length %u != full decoder length %u (window %u)",
                 mini.Length, full.Length, Window);
        return -1;
    }

    return 0;
}


//
// Run the full invariant sweep (truncation, window independence, mini
// agreement) for one case across the vendor/feature matrix.
//
static int
XdfSweepCase(
    const XDF_CASE *Case,
    unsigned int DefCode,
    char *Reason,
    unsigned int ReasonSize
)
{
    static const unsigned int vendors[] = { ND_VEND_ANY, ND_VEND_INTEL, ND_VEND_AMD };
    static const unsigned int features[] = { ND_FEAT_ALL, ND_FEAT_NONE };
    static const unsigned int options[] = { 0, ND_OPTION_ONLY_EXPLICIT_OPERANDS };

    XDF_CASE local = *Case;

    local.DefCode = DefCode;

    for (unsigned int v = 0; v < sizeof(vendors) / sizeof(vendors[0]); v++)
    {
        for (unsigned int f = 0; f < sizeof(features) / sizeof(features[0]); f++)
        {
            for (unsigned int o = 0; o < sizeof(options) / sizeof(options[0]); o++)
            {
                for (unsigned int window = 1; window <= local.Len; window++)
                {
                    int succeeded = 0;

                    if (XdfCheckWindow(&local, window, options[o], vendors[v], features[f],
                                       Reason, ReasonSize, &succeeded) != 0)
                    {
                        return -1;
                    }

                    if (XdfCheckMini(&local, window, options[o], vendors[v], features[f],
                                     Reason, ReasonSize) != 0)
                    {
                        return -1;
                    }

                    // A truncated window may not decode to something longer
                    // than the window; the checks above enforce this, but make
                    // the intent explicit for the whole-window decode too.
                    if (succeeded && window < local.Len)
                    {
                        INSTRUX instrux;
                        unsigned char *copy = XdfExactWindow(local.Bytes, window);
                        NDSTATUS status;

                        memset(&instrux, 0, sizeof(instrux));
                        status = NdDecodeEx2(&instrux, copy, window, local.DefCode, local.DefCode, local.DefCode, ND_VEND_ANY);
                        free(copy);

                        if (ND_SUCCESS(status) && instrux.Length > window)
                        {
                            snprintf(Reason, ReasonSize,
                                     "truncated window %u decoded length %u", window, instrux.Length);
                            return -1;
                        }
                    }
                }
            }
        }
    }

    // Finally, the SKIP_CACHE_IBYTES fast path, which decodes straight from
    // the caller's buffer rather than a private copy and is a separate code
    // path for the byte fetch.
    {
        INSTRUX_MINI cached;
        INSTRUX_MINI direct;
        NDSTATUS cachedStatus;
        NDSTATUS directStatus;

        memset(&cached, 0, sizeof(cached));
        memset(&direct, 0, sizeof(direct));

        cachedStatus = XdfDecodeWindowMini(&local, local.Len, 0, ND_VEND_ANY, ND_FEAT_ALL, &cached);
        directStatus = XdfDecodeWindowMini(&local, local.Len, ND_OPTION_SKIP_CACHE_IBYTES,
                                           ND_VEND_ANY, ND_FEAT_ALL, &direct);

        if ((ND_SUCCESS(cachedStatus) ? 1 : 0) != (ND_SUCCESS(directStatus) ? 1 : 0) ||
            (ND_SUCCESS(cachedStatus) && cached.Length != direct.Length))
        {
            snprintf(Reason, ReasonSize,
                     "SKIP_CACHE_IBYTES disagrees: cached=%08x direct=%08x", cachedStatus, directStatus);
            return -1;
        }
    }

    return 0;
}


//
// Shrink a failing case to the smallest prefix of the bytes that still
// reproduces a failure in the same decode mode. Only prefixes are considered,
// so every candidate is a legal truncation of the original sample and the
// minimized sample can always be replayed byte for byte.
//
static void
XdfMinimize(
    XDF_FAILURE *Failure
)
{
    // Start from the failing window, not the whole buffer: bytes past the
    // window were never seen by the decoder and are irrelevant.
    unsigned int best = Failure->Window;
    unsigned int originalWindow = Failure->Window;

    for (unsigned int window = 1; window < originalWindow; window++)
    {
        XDF_CASE caseCopy;
        char reason[256];
        int succeeded = 0;

        memset(&caseCopy, 0, sizeof(caseCopy));
        memcpy(caseCopy.Bytes, Failure->Bytes, window);
        caseCopy.Len = window;
        caseCopy.DefCode = Failure->DefCode;
        caseCopy.Tag = XDF_TAG_LEGACY;

        if (XdfCheckWindow(&caseCopy, window, 0, ND_VEND_ANY, ND_FEAT_ALL,
                           reason, sizeof(reason), &succeeded) != 0)
        {
            best = window;
            break;
        }
    }

    Failure->Window = best;
    Failure->Len = best;
}


static void
XdfWriteHex(
    FILE *File,
    const unsigned char *Bytes,
    unsigned int Len
)
{
    for (unsigned int i = 0; i < Len; i++)
    {
        fprintf(File, "%02x", Bytes[i]);
    }
}


//
// Persist a failure: raw bytes, a text description and a minimal reproducer
// case file that `replay --case` can reload.
//
static int
XdfReportFailure(
    const XDF_FAILURE *Failure,
    const char *ReportDir
)
{
    char path[1024];
    FILE *file;

    snprintf(path, sizeof(path), "%s/%s-%u-%u-%s.bin",
             ReportDir, Failure->Tag, Failure->DefCode, Failure->Window, "case");
    file = fopen(path, "wb");
    if (file != NULL)
    {
        fwrite(Failure->Bytes, 1, Failure->Len, file);
        fclose(file);
    }

    snprintf(path, sizeof(path), "%s/%s-%u-%u-%s.case",
             ReportDir, Failure->Tag, Failure->DefCode, Failure->Window, "repro");
    file = fopen(path, "w");
    if (file == NULL)
    {
        return -1;
    }

    // The reproducer is self-describing text: one header line with the decode
    // parameters, then the instruction bytes in hex.
    fprintf(file, "# xdf-repro v1\n");
    fprintf(file, "tag=%s\n", Failure->Tag);
    fprintf(file, "mode=%s\n", XdfModeName(Failure->DefCode));
    fprintf(file, "len=%u\n", Failure->Len);
    fprintf(file, "window=%u\n", Failure->Window);
    fprintf(file, "reason=%s\n", Failure->Reason);
    fprintf(file, "bytes=");
    XdfWriteHex(file, Failure->Bytes, Failure->Len);
    fprintf(file, "\n");
    fclose(file);

    snprintf(path, sizeof(path), "%s/%s-%u-%u-%s.txt",
             ReportDir, Failure->Tag, Failure->DefCode, Failure->Window, "desc");
    file = fopen(path, "w");
    if (file != NULL)
    {
        fprintf(file, "tag       : %s\n", Failure->Tag);
        fprintf(file, "mode      : %s-bit\n", XdfModeName(Failure->DefCode));
        fprintf(file, "bytes     : ");
        XdfWriteHex(file, Failure->Bytes, Failure->Len);
        fprintf(file, "\n");
        fprintf(file, "window    : %u\n", Failure->Window);
        fprintf(file, "reason    : %s\n", Failure->Reason);
        fclose(file);
    }

    printf("[FAIL] %s: %s\n", Failure->Tag, Failure->Reason);
    printf("       mode=%s window=%u bytes=", XdfModeName(Failure->DefCode), Failure->Window);
    XdfWriteHex(stdout, Failure->Bytes, Failure->Len);
    printf("\n");
    printf("       sample written to %s/%s-%u-%u-repro.case\n",
           ReportDir, Failure->Tag, Failure->DefCode, Failure->Window);

    return 0;
}


//
// Record a failed case: shrink it, persist the sample, and return the updated
// report counter.
//
static unsigned int
XdfRecordFailure(
    const XDF_CASE *Case,
    unsigned int Window,
    const char *Reason,
    const char *ReportDir,
    unsigned int Reports
)
{
    XDF_FAILURE failure;

    memset(&failure, 0, sizeof(failure));
    failure.Failed = 1;
    failure.Len = Case->Len;
    failure.Window = Window;
    failure.DefCode = Case->DefCode;
    snprintf(failure.Tag, sizeof(failure.Tag), "%s", XdfTagName(Case->Tag));
    snprintf(failure.Reason, sizeof(failure.Reason), "%s", Reason);
    memcpy(failure.Bytes, Case->Bytes, Case->Len);

    XdfMinimize(&failure);
    XdfReportFailure(&failure, ReportDir);

    return Reports + 1;
}


static int
XdfRun(
    unsigned long long Seed,
    unsigned long long Cases,
    int ModeFilter,
    const char *ReportDir,
    int Verbose
)
{
    unsigned long long decoded = 0;
    unsigned int reports = 0;

    for (unsigned long long index = 0; index < Cases; index++)
    {
        XDF_CASE base;
        unsigned int modes[3];
        unsigned int modeCount = 0;
        char reason[256];

        XdfGenerateCase(Seed, index, &base);

        // A generator case carries its own preferred mode, but each case is
        // also useful when decoded in every other mode (especially 16/32 bit
        // where the same bytes mean something completely different).
        modes[modeCount++] = base.DefCode;
        for (unsigned int m = 0; m < 3; m++)
        {
            if (m != base.DefCode)
            {
                modes[modeCount++] = m;
            }
        }

        for (unsigned int m = 0; m < modeCount; m++)
        {
            XDF_CASE current = base;

            if (ModeFilter >= 0 && (unsigned int)ModeFilter != modes[m])
            {
                continue;
            }

            current.DefCode = modes[m];

            for (unsigned int window = 1; window <= current.Len; window++)
            {
                int succeeded = 0;

                if (XdfCheckWindow(&current, window, 0, ND_VEND_ANY, ND_FEAT_ALL,
                                   reason, sizeof(reason), &succeeded) != 0)
                {
                    reports = XdfRecordFailure(&current, window, reason, ReportDir, reports);

                    if (reports >= XDF_MAX_REPORTS)
                    {
                        printf("[!] stopping after %u reported failures\n", reports);
                        return 1;
                    }

                    continue;
                }

                if (succeeded)
                {
                    decoded++;
                }
            }

            // The deeper sweep (vendor/feature/option matrix) is only run on
            // the case's own natural mode: it multiplies work by 12.
            if (current.DefCode == base.DefCode)
            {
                if (XdfSweepCase(&current, current.DefCode, reason, sizeof(reason)) != 0)
                {
                    reports = XdfRecordFailure(&current, current.Len, reason, ReportDir, reports);

                    if (reports >= XDF_MAX_REPORTS)
                    {
                        printf("[!] stopping after %u reported failures\n", reports);
                        return 1;
                    }
                }
            }
        }

        if (Verbose && (index + 1) % 1000 == 0)
        {
            printf("[*] %llu cases, %llu decodes, %u reported failures\n", index + 1, decoded, reports);
        }
    }

    printf("[*] seed=%llu cases=%llu decodes=%llu failures=%u\n", Seed, Cases, decoded, reports);

    return reports == 0 ? 0 : 1;
}


//
// Replay a minimal reproducer file produced by XdfReportFailure.
//
static int
XdfReplay(
    const char *Path
)
{
    char line[1024];
    char bytesHex[1024] = {0};
    char modeText[16] = {0};
    char tag[64] = {0};
    unsigned int len = 0;
    unsigned int window = 0;
    FILE *file;
    XDF_CASE testCase;
    char reason[256];
    int succeeded = 0;
    NDSTATUS status;
    INSTRUX instrux;

    file = fopen(Path, "r");
    if (file == NULL)
    {
        fprintf(stderr, "xdf: cannot open %s\n", Path);
        return 2;
    }

    while (fgets(line, sizeof(line), file) != NULL)
    {
        line[strcspn(line, "\r\n")] = '\0';

        if (strncmp(line, "bytes=", 6) == 0)
        {
            snprintf(bytesHex, sizeof(bytesHex), "%.1000s", line + 6);
        }
        else if (strncmp(line, "mode=", 5) == 0)
        {
            snprintf(modeText, sizeof(modeText), "%.15s", line + 5);
        }
        else if (strncmp(line, "tag=", 4) == 0)
        {
            snprintf(tag, sizeof(tag), "%.63s", line + 4);
        }
        else if (strncmp(line, "len=", 4) == 0)
        {
            len = (unsigned int)strtoul(line + 4, NULL, 10);
        }
        else if (strncmp(line, "window=", 7) == 0)
        {
            window = (unsigned int)strtoul(line + 7, NULL, 10);
        }
    }

    fclose(file);

    if (bytesHex[0] == '\0' || modeText[0] == '\0')
    {
        fprintf(stderr, "xdf: malformed reproducer %s\n", Path);
        return 2;
    }

    memset(&testCase, 0, sizeof(testCase));
    testCase.Len = (unsigned int)(strlen(bytesHex) / 2);

    if (testCase.Len == 0 || testCase.Len > XDF_GEN_MAX)
    {
        fprintf(stderr, "xdf: bad byte count in %s\n", Path);
        return 2;
    }

    for (unsigned int i = 0; i < testCase.Len; i++)
    {
        unsigned int value = 0;

        if (sscanf(bytesHex + 2 * i, "%2x", &value) != 1)
        {
            fprintf(stderr, "xdf: bad hex in %s\n", Path);
            return 2;
        }

        testCase.Bytes[i] = (unsigned char)value;
    }

    testCase.DefCode = (unsigned int)XdfParseMode(modeText);
    if (testCase.DefCode == (unsigned int)-1)
    {
        fprintf(stderr, "xdf: bad mode in %s\n", Path);
        return 2;
    }

    if (window == 0 || window > testCase.Len)
    {
        window = testCase.Len;
    }

    (void)len;

    printf("[*] replaying %s: tag=%s mode=%s len=%u window=%u\n",
           Path, tag, XdfModeName(testCase.DefCode), testCase.Len, window);

    if (XdfCheckWindow(&testCase, window, 0, ND_VEND_ANY, ND_FEAT_ALL,
                       reason, sizeof(reason), &succeeded) != 0)
    {
        printf("[FAIL] %s\n", reason);
        return 1;
    }

    memset(&instrux, 0, sizeof(instrux));
    status = XdfDecodeWindow(&testCase, window, 0, ND_VEND_ANY, ND_FEAT_ALL, &instrux);

    if (ND_SUCCESS(status))
    {
#if !defined(BDDISASM_NO_MNEMONIC) && !defined(BDDISASM_NO_FORMAT)
        char text[256];

        if (ND_SUCCESS(NdToText(&instrux, 0, sizeof(text), text)))
        {
            printf("[OK] decoded: %s (len %u, mnemonic %s)\n",
                   text, instrux.Length, instrux.Mnemonic ? instrux.Mnemonic : "?");
        }
        else
#endif // !BDDISASM_NO_MNEMONIC && !BDDISASM_NO_FORMAT
        {
            printf("[OK] decoded (len %u)\n", instrux.Length);
        }
    }
    else
    {
        printf("[OK] rejected with %08x (no instruction fabricated)\n", status);
    }

    return 0;
}


//
// Built-in regression cases. These are hand-picked encodings that pin down
// the boundaries the generator explores: legacy prefix combinations, VEX/EVEX
// payloads, ModRM/SIB/displacement forms, immediate widths and truncated
// windows. They make `self-test` meaningful even without a corpus run.
//
typedef struct _XDF_FIXED_CASE
{
    const char          *Name;
    unsigned int        DefCode;
    unsigned int        Len;
    const unsigned char Bytes[XDF_GEN_MAX];
} XDF_FIXED_CASE;

static const XDF_FIXED_CASE gFixedCases[] = {
    // Plain legacy, one byte.
    { "nop",                ND_CODE_32, 1, { 0x90 } },
    // Legacy prefix run followed by a ModRM instruction.
    { "mov-r32-r32",        ND_CODE_32, 2, { 0x8B, 0xC1 } },
    { "mov-r64-r64-rex",    ND_CODE_64, 3, { 0x48, 0x8B, 0xC1 } },
    { "opsize-prefix",      ND_CODE_32, 3, { 0x66, 0x8B, 0xC1 } },
    { "addrsize-prefix",    ND_CODE_32, 3, { 0x67, 0x8B, 0x06 } },
    // SIB + displacement.
    { "mov-sib",            ND_CODE_64, 4, { 0x8B, 0x04, 0x24 } },
    { "mov-disp8",          ND_CODE_64, 4, { 0x8B, 0x44, 0x24, 0x08 } },
    { "mov-disp32",         ND_CODE_64, 7, { 0x8B, 0x84, 0x24, 0x78, 0x56, 0x34, 0x12 } },
    // RIP-relative.
    { "mov-riprel",         ND_CODE_64, 6, { 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00 } },
    // Immediate widths.
    { "mov-eax-imm32",      ND_CODE_32, 5, { 0xB8, 0x78, 0x56, 0x34, 0x12 } },
    { "mov-rax-imm64",      ND_CODE_64, 10, { 0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 } },
    { "add-eax-imm8",       ND_CODE_32, 2, { 0x04, 0x7F } },
    { "enter-imm16-imm8",   ND_CODE_32, 4, { 0xC8, 0x34, 0x12, 0x05 } },
    // Relative offset.
    { "jmp-rel8",           ND_CODE_32, 2, { 0xEB, 0x05 } },
    { "jmp-rel32",          ND_CODE_32, 5, { 0xE9, 0x00, 0x00, 0x00, 0x00 } },
    // Moffset.
    { "mov-al-moff32",      ND_CODE_32, 5, { 0xA0, 0x11, 0x22, 0x33, 0x44 } },
    // Far address.
    { "callf-ptr16-32",     ND_CODE_32, 7, { 0x9A, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 } },
    // VEX.
    { "vex2-vmovdqu",       ND_CODE_64, 4, { 0xC5, 0xFA, 0x6F, 0xC1 } },
    { "vex3-vmovdqu",       ND_CODE_64, 5, { 0xC4, 0xE1, 0x7A, 0x6F, 0xC1 } },
    { "vex0f38",            ND_CODE_64, 5, { 0xC4, 0xE2, 0x79, 0x00, 0xC1 } },
    // EVEX.
    { "evex-vmovdqu",       ND_CODE_64, 6, { 0x62, 0xF1, 0x7F, 0x48, 0x6F, 0xC1 } },
    { "evex-mask-bcst",     ND_CODE_64, 7, { 0x62, 0xF1, 0x7C, 0xC9, 0x58, 0x44, 0x24, 0x08 } },
    // XOP.
    { "xop",                ND_CODE_64, 5, { 0x8F, 0xE8, 0x78, 0xC0, 0xC1 } },
    // 3DNow! (opcode is the last byte).
    { "3dnow",              ND_CODE_32, 4, { 0x0F, 0x0F, 0xC1, 0x9E } },
    // 0F 38 / 0F 3A.
    { "0f38-pshufb",        ND_CODE_64, 5, { 0x66, 0x0F, 0x38, 0x00, 0xC1 } },
    { "0f3a-palignr",       ND_CODE_64, 6, { 0x66, 0x0F, 0x3A, 0x0F, 0xC1, 0x04 } },
    // REX2 / APX, 64-bit only.
    { "rex2-mov",           ND_CODE_64, 4, { 0xD5, 0x00, 0x8B, 0xC1 } },
    // 16-bit addressing forms.
    { "mov-a16",            ND_CODE_16, 3, { 0x8B, 0x06 } },
    { "mov-a16-disp8",      ND_CODE_16, 4, { 0x8B, 0x46, 0x10 } },
    { "mov-a16-disp16",     ND_CODE_16, 5, { 0x8B, 0x86, 0x34, 0x12 } },
    // 16-bit mode running out of bytes with a 16-bit displacement.
    { "trunc-a16-disp16",   ND_CODE_16, 4, { 0x8B, 0x86, 0x34, 0x12 } },
    // Truncated windows: the full bytes are longer than the window used.
    { "vex-truncated",      ND_CODE_64, 3, { 0xC5, 0xFA, 0x6F } },
    { "evex-truncated",     ND_CODE_64, 4, { 0x62, 0xF1, 0x7F, 0x48 } },
    { "prefix-only",        ND_CODE_32, 3, { 0x66, 0x67, 0xF3 } },
    // Over-long instruction: 16 prefixes then a NOP.
    { "too-long",           ND_CODE_32, 16, { 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                                              0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x90 } },
    // Universal NOP space, feature dependent.
    { "nop-0f1f",           ND_CODE_64, 4, { 0x0F, 0x1F, 0x40, 0x00 } },
    // Invalid in 64-bit only.
    { "aam-64",             ND_CODE_64, 2, { 0xD4, 0x0A } },
    { "aam-32",             ND_CODE_32, 2, { 0xD4, 0x0A } },
};


static int
XdfSelfTest(void)
{
    unsigned int failures = 0;

    for (unsigned int i = 0; i < sizeof(gFixedCases) / sizeof(gFixedCases[0]); i++)
    {
        XDF_CASE testCase;
        char reason[256];

        memset(&testCase, 0, sizeof(testCase));
        memcpy(testCase.Bytes, gFixedCases[i].Bytes, gFixedCases[i].Len);
        testCase.Len = gFixedCases[i].Len;
        testCase.DefCode = gFixedCases[i].DefCode;
        testCase.Tag = XDF_TAG_LEGACY;

        if (XdfSweepCase(&testCase, testCase.DefCode, reason, sizeof(reason)) != 0)
        {
            printf("[FAIL] %-20s mode=%s: %s\n",
                   gFixedCases[i].Name, XdfModeName(testCase.DefCode), reason);
            failures++;
        }
        else
        {
            printf("[ ok ] %-20s mode=%s\n", gFixedCases[i].Name, XdfModeName(testCase.DefCode));
        }
    }

    printf("[*] self-test: %u/%u fixture groups passed\n",
           (unsigned int)(sizeof(gFixedCases) / sizeof(gFixedCases[0])) - failures,
           (unsigned int)(sizeof(gFixedCases) / sizeof(gFixedCases[0])));

    return failures == 0 ? 0 : 1;
}


static void
XdfUsage(
    const char *Program
)
{
    printf("usage: %s run    [--seed N] [--cases N] [--mode 16|32|64|all]\n"
           "                [--report-dir DIR] [--verbose]\n"
           "       %s replay --case FILE\n"
           "       %s regen  --seed N --index N [--mode 16|32|64]\n"
           "       %s self-test\n"
           "       %s list-ops\n",
           Program, Program, Program, Program, Program);
}


static int
XdfCmdRegen(
    unsigned long long Seed,
    unsigned long long Index,
    int ModeFilter
)
{
    XDF_CASE testCase;

    XdfGenerateCase(Seed, Index, &testCase);

    if (ModeFilter >= 0)
    {
        testCase.DefCode = (unsigned int)ModeFilter;
    }

    printf("tag=%s\n", XdfTagName(testCase.Tag));
    printf("mode=%s\n", XdfModeName(testCase.DefCode));
    printf("bytes=");
    XdfWriteHex(stdout, testCase.Bytes, testCase.Len);
    printf("\n");

    return 0;
}


int
main(
    int argc,
    char **argv
)
{
    if (argc < 2)
    {
        XdfUsage(argv[0]);
        return 2;
    }

    if (strcmp(argv[1], "run") == 0)
    {
        unsigned long long seed = 1;
        unsigned long long cases = 20000;
        int modeFilter = -1;
        const char *reportDir = XDF_REPORT_DIR_DEFAULT;
        int verbose = 0;

        for (int i = 2; i < argc; i++)
        {
            if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc)
            {
                seed = strtoull(argv[++i], NULL, 0);
            }
            else if (strcmp(argv[i], "--cases") == 0 && i + 1 < argc)
            {
                cases = strtoull(argv[++i], NULL, 0);
            }
            else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc)
            {
                if (strcmp(argv[i + 1], "all") != 0)
                {
                    modeFilter = XdfParseMode(argv[i + 1]);
                    if (modeFilter < 0)
                    {
                        XdfUsage(argv[0]);
                        return 2;
                    }
                }
                i++;
            }
            else if (strcmp(argv[i], "--report-dir") == 0 && i + 1 < argc)
            {
                reportDir = argv[++i];
            }
            else if (strcmp(argv[i], "--verbose") == 0)
            {
                verbose = 1;
            }
            else
            {
                XdfUsage(argv[0]);
                return 2;
            }
        }

        return XdfRun(seed, cases, modeFilter, reportDir, verbose);
    }

    if (strcmp(argv[1], "replay") == 0)
    {
        const char *path = NULL;

        for (int i = 2; i < argc; i++)
        {
            if (strcmp(argv[i], "--case") == 0 && i + 1 < argc)
            {
                path = argv[++i];
            }
        }

        if (path == NULL)
        {
            XdfUsage(argv[0]);
            return 2;
        }

        return XdfReplay(path);
    }

    if (strcmp(argv[1], "regen") == 0)
    {
        unsigned long long seed = 0;
        unsigned long long index = 0;
        int modeFilter = -1;

        for (int i = 2; i < argc; i++)
        {
            if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc)
            {
                seed = strtoull(argv[++i], NULL, 0);
            }
            else if (strcmp(argv[i], "--index") == 0 && i + 1 < argc)
            {
                index = strtoull(argv[++i], NULL, 0);
            }
            else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc)
            {
                modeFilter = XdfParseMode(argv[++i]);
                if (modeFilter < 0)
                {
                    XdfUsage(argv[0]);
                    return 2;
                }
            }
        }

        return XdfCmdRegen(seed, index, modeFilter);
    }

    if (strcmp(argv[1], "self-test") == 0)
    {
        return XdfSelfTest();
    }

    if (strcmp(argv[1], "list-ops") == 0)
    {
        for (unsigned int i = 0; i < XDF_TAG_MAX; i++)
        {
            printf("%u %s\n", i, XdfTagName(i));
        }

        return 0;
    }

    XdfUsage(argv[0]);
    return 2;
}
