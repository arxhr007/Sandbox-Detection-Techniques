/*
 * test_detector.c -- framework-free unit tests for the pure scoring core.
 *
 * Links only against detector.c (no Windows API), so it builds and runs on any
 * platform / CI runner with a stock C compiler.
 */
#include "detector.h"

#include <stdio.h>
#include <string.h>

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond) do {                                            \
    g_checks++;                                                     \
    if (!(cond)) {                                                  \
        g_failures++;                                               \
        printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);     \
    }                                                              \
} while (0)

static void test_empty_detector(void) {
    SandboxDetector* d = newSandboxDetector();
    CHECK(d != NULL);
    CHECK(d->resultCount == 0);
    CHECK(d->score == 0);
    CHECK(d->threshold == SANDBOX_SCORE_THRESHOLD);
    CHECK(detectorMaxScore(d) == 0);
    finalizeVerdict(d);
    CHECK(d->isInSandbox == false);
    freeSandboxDetector(d);
}

static void test_score_accumulates_only_detected(void) {
    SandboxDetector* d = newSandboxDetector();
    addResult(d, "System", "a", WEIGHT_STRONG, true);   /* +3 */
    addResult(d, "System", "b", WEIGHT_MEDIUM, false);  /* +0 */
    addResult(d, "User",   "c", WEIGHT_WEAK, true);     /* +1 */
    CHECK(d->resultCount == 3);
    CHECK(d->score == 4);
    CHECK(detectorMaxScore(d) == WEIGHT_STRONG + WEIGHT_MEDIUM + WEIGHT_WEAK); /* 6 */
    /* stored fields */
    CHECK(strcmp(d->results[0].test, "a") == 0);
    CHECK(d->results[0].weight == WEIGHT_STRONG);
    CHECK(d->results[1].detected == false);
    freeSandboxDetector(d);
}

static void test_verdict_boundary(void) {
    SandboxDetector* d = newSandboxDetector();
    d->threshold = 5;
    addResult(d, "Runtime", "x", 4, true); /* score 4, below threshold */
    finalizeVerdict(d);
    CHECK(d->isInSandbox == false);
    addResult(d, "Runtime", "y", 1, true); /* score 5, at threshold */
    finalizeVerdict(d);
    CHECK(d->isInSandbox == true);
    freeSandboxDetector(d);
}

static void test_threshold_override(void) {
    SandboxDetector* d = newSandboxDetector();
    addResult(d, "Runtime", "x", 3, true); /* score 3 */
    d->threshold = 3;
    finalizeVerdict(d);
    CHECK(d->isInSandbox == true);   /* 3 >= 3 */
    d->threshold = 4;
    finalizeVerdict(d);
    CHECK(d->isInSandbox == false);  /* 3 < 4 */
    freeSandboxDetector(d);
}

static void test_growth_past_capacity(void) {
    SandboxDetector* d = newSandboxDetector();
    int n = 50; /* initial capacity is 20 -> forces at least one realloc */
    for (int i = 0; i < n; i++) {
        addResult(d, "System", "bulk", WEIGHT_WEAK, true);
    }
    CHECK(d->resultCount == n);
    CHECK(d->score == n * WEIGHT_WEAK);
    CHECK(d->capacity >= n);
    freeSandboxDetector(d);
}

int main(void) {
    test_empty_detector();
    test_score_accumulates_only_detected();
    test_verdict_boundary();
    test_threshold_override();
    test_growth_past_capacity();

    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    if (g_failures == 0) {
        printf("ALL TESTS PASSED\n");
        return 0;
    }
    printf("TESTS FAILED\n");
    return 1;
}
