# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an RFC 1035 DNS protocol implementation using TypeScript, Bun runtime, and the Effect library. The project implements DNS message parsing and encoding according to RFC 1035 specifications.

## Development Commands

### Install Dependencies
```bash
bun install
```

### Running Tests
```bash
# Run all tests once
bun test

# Run tests in watch mode
bun run test:watch

# Run tests with coverage
bun run test:coverage

# Run a specific test file
bun test rfc-1035.test.ts
```

### Running the Application
```bash
bun run index.ts
```

## Architecture

The codebase implements DNS protocol structures using Effect's Schema library for validation and type safety:

- **Type System**: Uses Effect Schema for defining and validating DNS protocol types (Nibble, Uint8, Uint16, etc.)
- **DNS Message Structure**: Implements Header and Question sections according to RFC 1035
- **Encoding/Decoding**: Provides bidirectional transformation between TypeScript objects and Uint8Arrays
- **Testing**: Uses property-based testing with Fast-Check through @effect/vitest

### Key Components

1. **index.ts**: Main implementation file containing:
   - DNS type definitions (Bit, Nibble, Uint8, Uint16, etc.)
   - Header structure with all RFC 1035 fields
   - Question structure for DNS queries
   - Encoding/decoding transformations using Effect Schema

2. **rfc-1035.test.ts**: Test suite using property-based testing to verify:
   - Header encoding/decoding roundtrip properties
   - Edge cases (all-zeros, all-ones headers)
   - Invalid input handling

### Effect Library Usage

This project heavily uses Effect for:
- Schema validation and transformations
- Error handling with ParseResult
- Property-based testing through @effect/vitest
- Type-safe encoding/decoding of binary data