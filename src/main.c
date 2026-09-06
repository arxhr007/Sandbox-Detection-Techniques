/*
 * main.c -- CLI entry point for the sandbox detector.
 *
 * Educational proof-of-concept. Runs environment checks and prints a weighted
 * verdict. No payload, no evasion.  By ARXHR007 ;)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "detector.h"
#include "checks.h"

static void printUsage(const char* prog) {
    printf("Usage: %s [options]\n\n", prog);
    printf("Educational sandbox/VM detector. Runs checks and prints a weighted verdict.\n\n");
    printf("Options:\n");
    printf("  --json           Emit results as a JSON object (implies --no-wait)\n");
    printf("  --quiet          Print only the final verdict lines (implies --no-wait)\n");
    printf("  --threshold N    Override the sandbox score threshold (default %d)\n", SANDBOX_SCORE_THRESHOLD);
    printf("  --no-wait        Do not wait for a keypress before exiting\n");
    printf("  --help           Show this help and exit\n");
}

int main(int argc, char** argv) {
    bool jsonOutput = false;
    bool quiet = false;
    bool noWait = false;
    int threshold = SANDBOX_SCORE_THRESHOLD;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0) {
            jsonOutput = true;
        } else if (strcmp(argv[i], "--quiet") == 0) {
            quiet = true;
        } else if (strcmp(argv[i], "--no-wait") == 0) {
            noWait = true;
        } else if (strcmp(argv[i], "--threshold") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "error: --threshold requires a value\n");
                return 2;
            }
            char* end = NULL;
            long v = strtol(argv[++i], &end, 10);
            if (end == argv[i] || *end != '\0' || v < 0) {
                fprintf(stderr, "error: invalid threshold '%s'\n", argv[i]);
                return 2;
            }
            threshold = (int)v;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printUsage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "error: unknown option '%s' (try --help)\n", argv[i]);
            return 2;
        }
    }

    /* Machine/quiet output modes are meant for scripting -- never block on input. */
    if (jsonOutput || quiet) {
        noWait = true;
    }

    if (!quiet && !jsonOutput) {
        printf("Running sandbox detection...\n");
        printf("Please wait while tests are being performed (takes up to 10 seconds)...\n\n");
    }

    SandboxDetector* detector = newSandboxDetector();
    if (detector == NULL) {
        fprintf(stderr, "error: failed to allocate detector\n");
        return 1;
    }
    detector->threshold = threshold;

    runTests(detector);
    finalizeVerdict(detector);

    if (jsonOutput) {
        printResultsJson(detector);
    } else {
        printResults(detector, quiet);
    }

    int verdict = detector->isInSandbox ? 1 : 0;
    freeSandboxDetector(detector);

    if (!noWait) {
        printf("Press any key to exit...\n");
        getchar();
    }
    /* Exit code doubles as a scriptable signal: 0 = genuine, 3 = sandbox. */
    return verdict ? 3 : 0;
}
