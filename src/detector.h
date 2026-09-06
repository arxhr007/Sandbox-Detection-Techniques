/*
 * detector.h -- weighted sandbox-detection scoring core.
 *
 * Pure C: contains no Windows API dependency so it can be unit-tested on any
 * platform. All OS-specific probing lives in checks.c.
 */
#ifndef SANDBOX_DETECTOR_H
#define SANDBOX_DETECTOR_H

#include <stdbool.h>

/*
 * Weighted threshold model (see README "How the Verdict Works"). Each check
 * contributes its weight only when it fires; the verdict compares the summed
 * score against the detector's threshold.
 *
 *   WEIGHT_STRONG (3) - near-definitive VM/analysis artifacts
 *   WEIGHT_MEDIUM (2) - suggestive signals
 *   WEIGHT_WEAK   (1) - environmental hints only
 *
 * SANDBOX_SCORE_THRESHOLD is the default; it sits above the noise floor of a
 * genuine modern desktop run unattended (Win11 hypervisor bit via VBS + the two
 * "no activity" checks stack to 4). Override at runtime with --threshold.
 */
#define WEIGHT_WEAK   1
#define WEIGHT_MEDIUM 2
#define WEIGHT_STRONG 3
#define SANDBOX_SCORE_THRESHOLD 5

typedef struct {
    char category[32];
    char test[64];
    int weight;
    bool detected;
} DetectionResult;

typedef struct {
    DetectionResult* results;
    int resultCount;
    int capacity;
    int score;       /* sum of weights of detected checks */
    int threshold;   /* verdict fires when score >= threshold */
    bool isInSandbox;
} SandboxDetector;

/* Lifecycle. newSandboxDetector returns NULL on allocation failure. */
SandboxDetector* newSandboxDetector(void);
void freeSandboxDetector(SandboxDetector* detector);

/* Record one check result; accumulates weight into score when detected. */
void addResult(SandboxDetector* detector, const char* category, const char* test,
               int weight, bool detected);

/* Sum of every registered check's weight (denominator for the score line). */
int detectorMaxScore(const SandboxDetector* detector);

/* Set isInSandbox = (score >= threshold). Call after all checks are recorded. */
void finalizeVerdict(SandboxDetector* detector);

/* Human-readable output. quiet=true prints only the final verdict line. */
void printResults(const SandboxDetector* detector, bool quiet);

/* Machine-readable output (single JSON object on stdout). */
void printResultsJson(const SandboxDetector* detector);

#endif /* SANDBOX_DETECTOR_H */
