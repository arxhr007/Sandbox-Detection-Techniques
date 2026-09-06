/*
 * detector.c -- weighted scoring core + output formatting.
 * Pure C, no Windows headers (kept unit-testable on any platform).
 */
#include "detector.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

SandboxDetector* newSandboxDetector(void) {
    SandboxDetector* detector = (SandboxDetector*)malloc(sizeof(SandboxDetector));
    if (detector == NULL) {
        return NULL;
    }
    detector->capacity = 20;
    detector->resultCount = 0;
    detector->score = 0;
    detector->threshold = SANDBOX_SCORE_THRESHOLD;
    detector->isInSandbox = false;
    detector->results = (DetectionResult*)malloc(sizeof(DetectionResult) * detector->capacity);
    if (detector->results == NULL) {
        free(detector);
        return NULL;
    }
    return detector;
}

void freeSandboxDetector(SandboxDetector* detector) {
    if (detector == NULL) {
        return;
    }
    free(detector->results);
    free(detector);
}

void addResult(SandboxDetector* detector, const char* category, const char* test,
               int weight, bool detected) {
    if (detector->resultCount >= detector->capacity) {
        int newCapacity = detector->capacity * 2;
        DetectionResult* grown = (DetectionResult*)realloc(detector->results,
                                     sizeof(DetectionResult) * newCapacity);
        if (grown == NULL) {
            return; /* keep existing results; drop this one rather than crash */
        }
        detector->results = grown;
        detector->capacity = newCapacity;
    }
    DetectionResult* r = &detector->results[detector->resultCount];
    snprintf(r->category, sizeof(r->category), "%s", category);
    snprintf(r->test, sizeof(r->test), "%s", test);
    r->weight = weight;
    r->detected = detected;
    detector->resultCount++;
    if (detected) {
        detector->score += weight;
    }
}

int detectorMaxScore(const SandboxDetector* detector) {
    int maxScore = 0;
    for (int i = 0; i < detector->resultCount; i++) {
        maxScore += detector->results[i].weight;
    }
    return maxScore;
}

void finalizeVerdict(SandboxDetector* detector) {
    detector->isInSandbox = (detector->score >= detector->threshold);
}

void printResults(const SandboxDetector* detector, bool quiet) {
    if (!quiet) {
        printf("==== Sandbox Detection Results ====\n\n");
        const char* categories[] = {"Runtime", "System", "Hardware", "User", "Network"};
        int categoryCount = (int)(sizeof(categories) / sizeof(categories[0]));
        for (int i = 0; i < categoryCount; i++) {
            printf("--- %s Tests ---\n", categories[i]);
            for (int j = 0; j < detector->resultCount; j++) {
                if (strcmp(detector->results[j].category, categories[i]) == 0) {
                    const char* status = detector->results[j].detected ? "Detected!" : "Not detected";
                    printf("%-32s (weight %d): %s\n",
                           detector->results[j].test, detector->results[j].weight, status);
                }
            }
            printf("\n");
        }
    }

    int maxScore = detectorMaxScore(detector);
    int detectedCount = 0;
    for (int i = 0; i < detector->resultCount; i++) {
        if (detector->results[i].detected) {
            detectedCount++;
        }
    }

    if (!quiet) {
        printf("==== Overall Assessment ====\n");
    }
    printf("Weighted score: %d / %d (threshold %d)\n",
           detector->score, maxScore, detector->threshold);
    if (detector->isInSandbox) {
        printf("WARNING: System appears to be running in a sandbox or virtual environment!\n");
    } else {
        printf("System appears to be a genuine environment.\n");
    }
    if (!quiet) {
        int percentage = (detector->resultCount > 0)
                         ? (detectedCount * 100) / detector->resultCount : 0;
        printf("\nDetection ratio: %d/%d checks fired (%d%%)\n",
               detectedCount, detector->resultCount, percentage);
    }
}

/* Minimal JSON string escaper for the small ASCII test/category names. */
static void printJsonString(const char* s) {
    putchar('"');
    for (const char* p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\') {
            putchar('\\');
            putchar(c);
        } else if (c < 0x20) {
            printf("\\u%04x", c);
        } else {
            putchar(c);
        }
    }
    putchar('"');
}

void printResultsJson(const SandboxDetector* detector) {
    printf("{\n");
    printf("  \"results\": [\n");
    for (int i = 0; i < detector->resultCount; i++) {
        const DetectionResult* r = &detector->results[i];
        printf("    {\"category\": ");
        printJsonString(r->category);
        printf(", \"test\": ");
        printJsonString(r->test);
        printf(", \"weight\": %d, \"detected\": %s}%s\n",
               r->weight, r->detected ? "true" : "false",
               (i + 1 < detector->resultCount) ? "," : "");
    }
    printf("  ],\n");
    printf("  \"score\": %d,\n", detector->score);
    printf("  \"max_score\": %d,\n", detectorMaxScore(detector));
    printf("  \"threshold\": %d,\n", detector->threshold);
    printf("  \"is_sandbox\": %s\n", detector->isInSandbox ? "true" : "false");
    printf("}\n");
}
