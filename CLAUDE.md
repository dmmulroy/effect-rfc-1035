# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Development Commands

- **Install dependencies**: `bun install`
- **Run tests**: `bun test` (uses Vitest)
- **Watch tests**: `bun test:watch` 
- **Test coverage**: `bun test:coverage`
- **Type checking**: `bun typecheck`
- **Run main file**: `bun run index.ts`

## Architecture Overview

This is a TypeScript implementation of RFC 1035 (DNS protocol) using the Effect library for functional programming with type-safe schema validation and transformation.

### Core Structure

- **Entry Point**: `index.ts` re-exports from `src/index.js` for backwards compatibility
- **Main Module**: `src/index.ts` re-exports all core components
- **Type System**: Built on Effect Schema for runtime validation and type safety

### Key Components

1. **Types** (`src/types.ts`): Core DNS data types using Effect Schema
   - `Bit`, `Uint3`, `Uint8`, `Uint16`, `Uint31` - Bounded integer types
   - Each type includes validation ranges and descriptive identifiers

2. **Header** (`src/header.ts`): DNS message header implementation
   - 12-byte binary format following RFC 1035 Section 4.1.1
   - Bidirectional transformation between binary and structured data
   - Includes validation for protocol compliance (Z field must be 0, etc.)

3. **Labels** (`src/labels.ts`): DNS domain name label processing
4. **Questions** (`src/question.ts`): DNS query section handling  
5. **Resource Records** (`src/resource-record.ts`): DNS answer/authority/additional records
6. **Utilities** (`src/utils.ts`): Shared binary parsing helpers

### Effect Library Usage

This codebase heavily uses Effect's Schema system for:
- Runtime type validation with compile-time type safety  
- Bidirectional transformations between binary and structured data
- Composable validation with detailed error reporting
- Functional error handling with `Either` types


### Binary Data Handling

The codebase implements RFC 1035's binary wire format:
- Uses `DataView` for endian-safe byte manipulation
- Bit-level operations for packed header fields
- Validates byte lengths and field constraints
- Provides both sync and async decode/encode APIs

### Development Notes

- Uses Bun runtime but compatible with Node.js
- TypeScript with strict mode and Effect language service plugin
- All core types export both the schema and TypeScript interface
- Maintains backwards compatibility through re-exports

### Testing Strategy

- **Vitest** for test runner with Node.js environment
- **Property-based testing** with arbitraries (`tests/arbitraries.ts`)
- **Edge case testing** for protocol compliance
- **Component-specific tests** for each DNS section type
- Tests cover both valid data and malformed input validation

#### **CRITICAL RULE**: **NEVER** modify tests to accommodate incorrect implementation.

When working with tests and implementation code:

###### **DO**:
Write correct, sound, high-quality, and comprehensive tests
Ensure tests accurately reflect the intended behavior and requirements
Allow tests to fail when the implementation is incorrect
Focus exclusively on test correctness and completeness
Verify that test logic, assertions, and edge cases are properly covered

###### **DO NOT**:
Adjust, weaken, or modify tests to make them pass with incorrect implementation
Change test expectations to match flawed code behavior
Update or modify any implementation code
Compromise test quality to avoid test failures
Rationale:
The human follows Test-Driven Development (TDD) practices. Your role is to ensure test correctness and quality. Failing tests indicate implementation issues that the human will resolve through proper TDD cycles. Test integrity is paramount - tests must remain the source of truth for expected behavior.

**Remember**: It is not only acceptable but expected for tests to fail when implementation is incorrect. This is the foundation of effective TDD.

