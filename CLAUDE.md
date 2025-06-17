# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a TypeScript implementation of RFC-1035 (Domain Names - Implementation and Specification) using the Effect library. The project focuses on encoding and decoding DNS protocol messages.

## Development Commands

```bash
# Install dependencies
bun install

# Run tests
bun run test

# Run tests in watch mode
bun run test:watch

# Run tests with coverage
bun run test:coverage

# Type checking
bun run typecheck

# Run a single test file
bun test path/to/test.ts

# Run tests matching a pattern
bun test -t "pattern"
```

## Architecture

The codebase uses functional programming patterns with the Effect library:

- **Type System**: Custom numeric types (Nibble, Uint3, Bit, Uint8, Uint16, Uint31) with validation
- **Schemas**: Effect schemas define DNS structures (Header, Question, ResourceRecord)
- **Transformations**: `FromUint8Array` schemas handle binary encoding/decoding
- **Testing**: Property-based testing with FastCheck via Effect integration

Key implementation pattern:
1. Define schema for the DNS structure
2. Create transformation schema for binary format
3. Implement decode/encode functions using Schema.decodeUnknown/encodeUnknown

## Binary Protocol Implementation

Each DNS structure follows a consistent pattern:
- Schema definition using Effect Schema.Struct
- Binary transformation schema using Schema.transformOrFail with manual byte manipulation
- DataView for reading/writing multi-byte integers in network byte order (big-endian)
- Proper validation of RFC-1035 size limits and constraints

## Testing Strategy

Uses property-based testing with FastCheck arbitraries:
- `arbitraryDnsHeaderUint8Array`: Generates valid 12-byte headers
- `arbitraryDnsQuestionUint8Array`: Generates valid DNS questions with proper label encoding
- `arbitraryResourceRecordUint8Array`: Generates valid resource records
- Roundtrip tests ensure encode/decode are proper inverses
- Edge case testing for size limits (63-byte labels, 255-byte names, 31-bit TTL)

## Current Status

**Implemented**:
- Header encoding/decoding
- Question encoding/decoding
- ResourceRecord decoding (partial - missing name compression)

**TODO**:
- ResourceRecord encoding (see TODO comment in index.ts:748)
- Message answer/authority/additional sections
- Name compression/decompression (decompressName function at index.ts:755)