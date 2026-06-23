#include <check.h>
#include <stdlib.h>
#include <string.h>
#include "sandbox_detector.h"

START_TEST(test_buffer_reads_never_exceed_declared_length)
{
    // Invariant: Buffer reads never exceed the declared length
    const char *payloads[] = {
        "valid",  // Valid input
        "1234567890123456789012345678901234567890123456789012345678901234",  // 64 chars - boundary
        "A",  // Single char
        "12345678901234567890123456789012345678901234567890123456789012345",  // 65 chars - overflow
        "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"  // 128 chars - 2x overflow
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        SandboxDetector detector;
        detector.results = (DetectionResult*)malloc(sizeof(DetectionResult) * 10);
        detector.capacity = 10;
        detector.resultCount = 0;
        detector.isInSandbox = false;

        // This should not cause buffer overflow
        addResult(&detector, payloads[i], payloads[i], false);
        
        // Verify the strings were copied within bounds
        ck_assert_str_eq(detector.results[0].category, payloads[i]);
        ck_assert_str_eq(detector.results[0].test, payloads[i]);
        
        free(detector.results);
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_buffer_reads_never_exceed_declared_length);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}