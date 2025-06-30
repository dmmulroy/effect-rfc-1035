Testing Philosophy
CRITICAL RULE: NEVER modify tests to accommodate incorrect implementation.

When working with tests and implementation code:

DO:
Write correct, sound, high-quality, and comprehensive tests
Ensure tests accurately reflect the intended behavior and requirements
Allow tests to fail when the implementation is incorrect
Focus exclusively on test correctness and completeness
Verify that test logic, assertions, and edge cases are properly covered
DO NOT:
Adjust, weaken, or modify tests to make them pass with incorrect implementation
Change test expectations to match flawed code behavior
Update or modify any implementation code
Compromise test quality to avoid test failures
Rationale:
The human follows Test-Driven Development (TDD) practices. Your role is to ensure test correctness and quality. Failing tests indicate implementation issues that the human will resolve through proper TDD cycles. Test integrity is paramount - tests must remain the source of truth for expected behavior.

Remember: It is not only acceptable but expected for tests to fail when implementation is incorrect. This is the foundation of effective TDD.

