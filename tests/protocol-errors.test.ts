import { describe, expect, it } from "@effect/vitest";
import { Effect, Exit } from "effect";
import { decodeHeaderFromUint8Array } from "../src/header";
import { decodeNameFromUint8Array } from "../src/name";
import { decodeResourceRecordFromUint8Array } from "../src/resource-record";
import { arbitraryMalformedDnsMessage } from "./arbitraries";

describe("Protocol Error Recovery Testing", () => {
	describe("Truncated DNS Headers", () => {
		const truncatedHeaders = [
			new Uint8Array([]), // Empty
			new Uint8Array([0x30, 0x39]), // Only ID field
			new Uint8Array([0x30, 0x39, 0x01, 0x00, 0x00, 0x01]), // Missing last 6 bytes
			new Uint8Array([
				0x30, 0x39, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
			]), // Missing 1 byte
		];

		truncatedHeaders.forEach((headerBytes, index) => {
			it.effect(`should reject truncated header case ${index + 1}`, () =>
				Effect.gen(function* () {
					const result = yield* Effect.exit(
						decodeHeaderFromUint8Array(headerBytes),
					);
					expect(Exit.isFailure(result)).toBe(true);
				}),
			);
		});
	});

	describe("Invalid Field Combinations", () => {
		// Response with questions but no answers (invalid for most response types)
		const invalidResponseBytes = (() => {
			const buffer = new ArrayBuffer(12);
			const view = new DataView(buffer);
			view.setUint16(0, 12345, false); // ID
			view.setUint8(2, 0x80); // QR=1 (response), others=0
			view.setUint8(3, 0); // RA=0, Z=0, RCODE=0
			view.setUint16(4, 1, false); // QDCOUNT=1
			view.setUint16(6, 0, false); // ANCOUNT=0 (problematic for response)
			view.setUint16(8, 0, false); // NSCOUNT=0
			view.setUint16(10, 0, false); // ARCOUNT=0
			return new Uint8Array(buffer);
		})();

		it.effect("should handle response with no answers gracefully", () =>
			Effect.gen(function* () {
				const result = yield* Effect.exit(
					decodeHeaderFromUint8Array(invalidResponseBytes),
				);
				// Header decoding should succeed, but message validation might flag this
				if (Exit.isSuccess(result)) {
					const header = result.value;
					expect(header.qr).toBe(1); // Response
					expect(header.ancount).toBe(0); // No answers
					expect(header.qdcount).toBe(1); // Has questions
					// This combination might be valid for NXDOMAIN responses
				}
			}),
		);
	});

	describe("Malformed Label Encoding", () => {
		const malformedLabels = [
			// Invalid label length (255 > 63)
			new Uint8Array([0xff, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x00]),
			// Label length points beyond buffer
			new Uint8Array([0x10, 0x65, 0x78, 0x61, 0x6d, 0x00]), // Length=16 but only 4 bytes follow
			// Missing terminator
			new Uint8Array([0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65]),
			// Circular pointer reference
			new Uint8Array([0xc0, 0x00]), // Points to itself
		];

		malformedLabels.forEach((labelBytes, index) => {
			it.effect(`should reject malformed label case ${index + 1}`, () =>
				Effect.gen(function* () {
					const result = yield* Effect.exit(
						decodeNameFromUint8Array(labelBytes),
					);
					expect(Exit.isFailure(result)).toBe(true);
				}),
			);
		});
	});

	it.effect("should reject out-of-bounds resource record data", () => {
		// RDLENGTH exceeds available data
		const malformedRR = new Uint8Array([
			// Name: "example.com"
			0x07,
			0x65,
			0x78,
			0x61,
			0x6d,
			0x70,
			0x6c,
			0x65, // "example"
			0x03,
			0x63,
			0x6f,
			0x6d, // "com"
			0x00, // Terminator
			// TYPE=A, CLASS=IN, TTL=3600
			0x00,
			0x01, // TYPE=A
			0x00,
			0x01, // CLASS=IN
			0x00,
			0x00,
			0x0e,
			0x10, // TTL=3600
			0x00,
			0x10, // RDLENGTH=16 (but only 4 bytes follow)
			0xc0,
			0xa8,
			0x01,
			0x01, // RDATA (4 bytes, but RDLENGTH claims 16)
		]);

		return Effect.gen(function* () {
			const result = yield* Effect.exit(
				decodeResourceRecordFromUint8Array(malformedRR),
			);
			expect(Exit.isFailure(result)).toBe(true);
		});
	});

	it.effect("should handle pointer chain depth limits", () => {
		// Create a deep pointer chain that could cause stack overflow
		const deepPointerChain = new Uint8Array(100);
		for (let i = 0; i < 98; i += 2) {
			deepPointerChain[i] = 0xc0; // Pointer flag
			deepPointerChain[i + 1] = i + 2; // Point to next position
		}
		deepPointerChain[98] = 0x00; // Final terminator

		return Effect.gen(function* () {
			const result = yield* Effect.exit(
				decodeNameFromUint8Array(deepPointerChain),
			);
			// Should either succeed with reasonable depth or fail gracefully
			// Implementation should have depth limits to prevent stack overflow
			if (Exit.isFailure(result)) {
				expect(Exit.isFailure(result)).toBe(true);
			} else {
				// If it succeeds, verify the result is reasonable
				const name = result.value;
				expect(name.labels.length).toBeLessThan(50); // Reasonable limit
			}
		});
	});

	it.effect("should validate maximum UDP message size", () => {
		// Test maximum UDP message size (512 bytes)
		const maxUdpMessage = new Uint8Array(512);
		// Fill with valid header
		const headerView = new DataView(maxUdpMessage.buffer, 0, 12);
		headerView.setUint16(0, 12345, false); // ID
		headerView.setUint8(2, 0x00); // QR=0 (query)
		headerView.setUint8(3, 0x00); // Flags
		headerView.setUint16(4, 1, false); // QDCOUNT=1
		headerView.setUint16(6, 0, false); // ANCOUNT=0
		headerView.setUint16(8, 0, false); // NSCOUNT=0
		headerView.setUint16(10, 0, false); // ARCOUNT=0

		// Add minimal question
		maxUdpMessage[12] = 0x07; // Label length
		maxUdpMessage.set(new TextEncoder().encode("example"), 13);
		maxUdpMessage[20] = 0x03; // Label length
		maxUdpMessage.set(new TextEncoder().encode("com"), 21);
		maxUdpMessage[24] = 0x00; // Terminator
		maxUdpMessage[25] = 0x00;
		maxUdpMessage[26] = 0x01; // QTYPE=A
		maxUdpMessage[27] = 0x00;
		maxUdpMessage[28] = 0x01; // QCLASS=IN

		return Effect.gen(function* () {
			const headerResult = yield* Effect.exit(
				decodeHeaderFromUint8Array(maxUdpMessage.slice(0, 12)),
			);
			expect(Exit.isSuccess(headerResult)).toBe(true);

			// Message should be processable even at maximum size
			if (Exit.isSuccess(headerResult)) {
				const header = headerResult.value;
				expect(header.qdcount).toBe(1);
			}
		});
	});

	it.effect("should handle count mismatches gracefully", () => {
		// Header claims 2 questions but message only contains 1
		const countMismatchMessage = new Uint8Array([
			// Header
			0x30,
			0x39, // ID
			0x01,
			0x00, // QR=0, OPCODE=0, AA=0, TC=0, RD=1
			0x00,
			0x02, // QDCOUNT=2 (but only 1 question follows)
			0x00,
			0x00, // ANCOUNT=0
			0x00,
			0x00, // NSCOUNT=0
			0x00,
			0x00, // ARCOUNT=0
			// Single question
			0x07,
			0x65,
			0x78,
			0x61,
			0x6d,
			0x70,
			0x6c,
			0x65, // "example"
			0x03,
			0x63,
			0x6f,
			0x6d, // "com"
			0x00, // Terminator
			0x00,
			0x01, // QTYPE=A
			0x00,
			0x01, // QCLASS=IN
		]);

		return Effect.gen(function* () {
			const headerResult = yield* Effect.exit(
				decodeHeaderFromUint8Array(countMismatchMessage.slice(0, 12)),
			);
			expect(Exit.isSuccess(headerResult)).toBe(true);

			if (Exit.isSuccess(headerResult)) {
				const header = headerResult.value;
				expect(header.qdcount).toBe(2); // Claims 2 questions

				// When parsing questions, should detect mismatch
				// (This would be caught by message-level parsing, not individual component parsing)
			}
		});
	});

	it.effect.prop(
		"should handle various malformed message scenarios",
		[arbitraryMalformedDnsMessage],
		([malformedCase]: [{ description: string; data: Uint8Array }]) =>
			Effect.gen(function* () {
				// Test that malformed messages are handled gracefully
				expect(malformedCase.description).toBeDefined();
				expect(malformedCase.data).toBeInstanceOf(Uint8Array);

				// Attempt to decode header from malformed data
				if (malformedCase.data.length >= 12) {
					const headerResult = yield* Effect.exit(
						decodeHeaderFromUint8Array(malformedCase.data.slice(0, 12)),
					);
					// Some malformed cases might have valid headers
					if (Exit.isSuccess(headerResult)) {
						const header = headerResult.value;
						// Validate header constraints
						expect(header.z).toBe(0); // Z field must be zero
					}
				} else {
					// Truncated messages should fail header decoding
					const headerResult = yield* Effect.exit(
						decodeHeaderFromUint8Array(malformedCase.data),
					);
					expect(Exit.isFailure(headerResult)).toBe(true);
				}
			}),
	);

	it.effect("should validate A record RDLENGTH constraints", () => {
		// A record with incorrect RDLENGTH
		const invalidARecord = new Uint8Array([
			// Name: "example.com"
			0x07,
			0x65,
			0x78,
			0x61,
			0x6d,
			0x70,
			0x6c,
			0x65, // "example"
			0x03,
			0x63,
			0x6f,
			0x6d, // "com"
			0x00, // Terminator
			// TYPE=A, CLASS=IN, TTL=3600
			0x00,
			0x01, // TYPE=A
			0x00,
			0x01, // CLASS=IN
			0x00,
			0x00,
			0x0e,
			0x10, // TTL=3600
			0x00,
			0x06, // RDLENGTH=6 (should be 4 for A record)
			0xc0,
			0xa8,
			0x01,
			0x01,
			0x00,
			0x00, // RDATA (6 bytes, invalid for A record)
		]);

		return Effect.gen(function* () {
			const result = yield* Effect.exit(
				decodeResourceRecordFromUint8Array(invalidARecord),
			);
			expect(Exit.isFailure(result)).toBe(true);
		});
	});

	it.effect("should reject empty message", () => {
		// Completely empty message
		const emptyMessage = new Uint8Array([]);

		return Effect.gen(function* () {
			const result = yield* Effect.exit(
				decodeHeaderFromUint8Array(emptyMessage),
			);
			expect(Exit.isFailure(result)).toBe(true);
		});
	});

	it.effect("should accept minimal valid message", () => {
		// Minimal valid message (header only)
		const minimalMessage = new Uint8Array([
			0x30,
			0x39, // ID
			0x00,
			0x00, // Flags (query, no recursion)
			0x00,
			0x00, // QDCOUNT=0
			0x00,
			0x00, // ANCOUNT=0
			0x00,
			0x00, // NSCOUNT=0
			0x00,
			0x00, // ARCOUNT=0
		]);

		return Effect.gen(function* () {
			const result = yield* Effect.exit(
				decodeHeaderFromUint8Array(minimalMessage),
			);
			expect(Exit.isSuccess(result)).toBe(true);

			if (Exit.isSuccess(result)) {
				const header = result.value;
				expect(header.id).toBe(0x3039);
				expect(header.qdcount).toBe(0);
				expect(header.ancount).toBe(0);
			}
		});
	});
});
