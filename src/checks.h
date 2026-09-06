/*
 * checks.h -- Windows-specific sandbox/VM/debugger probes.
 * The implementation (checks.c) is the only translation unit that pulls in the
 * Win32 API; everything here operates on the pure SandboxDetector from detector.h.
 */
#ifndef SANDBOX_CHECKS_H
#define SANDBOX_CHECKS_H

#include "detector.h"

/* Run every registered detection check and record its result on the detector.
   Does not compute the verdict -- call finalizeVerdict() afterwards. */
void runTests(SandboxDetector* detector);

#endif /* SANDBOX_CHECKS_H */
