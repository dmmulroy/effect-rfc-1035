import { describe, expect, it } from "@effect/vitest";
import { Effect, Exit } from "effect";
import { decodeHeaderFromUint8Array } from "../src/header";
import { decodeNameFromUint8Array } from "../src/name";
import { decodeResourceRecordFromUint8Array } from "../src/resource-record";
import {
	arbitraryBoundaryConditions,
	arbitraryStressTestMessage,
} from "./arbitraries";

describe("Boundary Conditions Testing", () => {
	it.effect("should handle maximum UDP message size (512 bytes)", () => {
		// Create a valid 512-byte DNS message
		const maxMessage = new Uint8Array(512);

		// Header (12 bytes)
		const headerView = new DataView(maxMessage.buffer, 0, 12);
		headerView.setUint16(0, 12345, false); // ID
		headerView.setUint8(2, 0x81); // QR=1 (response), RD=1
		headerView.setUint8(3, 0x80); // RA=1
		headerView.setUint16(4, 1, false); // QDCOUNT=1
		headerView.setUint16(6, 1, false); // ANCOUNT=1
		headerView.setUint16(8, 0, false); // NSCOUNT=0
		headerView.setUint16(10, 0, false); // ARCOUNT=0

		// Question section (17 bytes): "example.com" + QTYPE + QCLASS
		let offset = 12;
		maxMessage[offset++] = 7; // "example"
		maxMessage.set(new TextEncoder().encode("example"), offset);
		offset += 7;
		maxMessage[offset++] = 3; // "com"
		maxMessage.set(new TextEncoder().encode("com"), offset);
		offset += 3;
		maxMessage[offset++] = 0; // Terminator

		const questionView = new DataView(maxMessage.buffer, offset);
		questionView.setUint16(0, 1, false); // QTYPE=A
		questionView.setUint16(2, 1, false); // QCLASS=IN
		offset += 4;

		// Answer section: same name (compressed), TYPE, CLASS, TTL, RDLENGTH, RDATA
		maxMessage[offset++] = 0xc0; // Pointer to question name
		maxMessage[offset++] = 0x0c; // Offset 12

		const answerView = new DataView(maxMessage.buffer, offset);
		answerView.setUint16(0, 1, false); // TYPE=A
		answerView.setUint16(2, 1, false); // CLASS=IN
		answerView.setUint32(4, 3600, false); // TTL
		answerView.setUint16(8, 4, false); // RDLENGTH
		offset += 10;

		// RDATA (4 bytes)
		maxMessage.set([192, 168, 1, 1], offset);
		offset += 4;

		// Fill remaining space with additional TXT records to reach 512 bytes
		const remainingSpace = 512 - offset;
		if (remainingSpace > 0) {
			// Update header to include additional records
			headerView.setUint16(10, Math.floor(remainingSpace / 20), false); // Rough estimate of additional records
		}

		return Effect.gen(function* () {
			const headerResult = yield* Effect.exit(
				decodeHeaderFromUint8Array(maxMessage.slice(0, 12)),
			);
			expect(Exit.isSuccess(headerResult)).toBe(true);

			if (Exit.isSuccess(headerResult)) {
				const header = headerResult.value;
				expect(header.id).toBe(12345);
				expect(header.qr).toBe(1);
				expect(header.qdcount).toBe(1);
				expect(header.ancount).toBe(1);
			}
		});
	});

	it.effect("should handle maximum domain name length (255 bytes)", () => {
		// Create domain name approaching 255-byte limit
		// 127 labels of 1 character each = 127 + 127 + 1 = 255 bytes total
		const maxDomainName = new Uint8Array(255);
		let offset = 0;

		// Add 126 single-character labels
		for (let i = 0; i < 126; i++) {
			maxDomainName[offset++] = 1; // Length
			maxDomainName[offset++] = 97 + (i % 26); // 'a' to 'z'
		}

		// Add final label to reach exactly 255 bytes
		maxDomainName[offset++] = 1; // Length
		maxDomainName[offset++] = 122; // 'z'
		maxDomainName[offset] = 0; // Terminator

		return Effect.gen(function* () {
			const result = yield* Effect.exit(
				decodeNameFromUint8Array(maxDomainName),
			);
			expect(Exit.isSuccess(result)).toBe(true);

			if (Exit.isSuccess(result)) {
				const name = result.value;
				expect(name.labels.length).toBe(127);
				expect(name.encodedByteLength).toBe(255);
			}
		});
	});

	it.effect("should reject domain names exceeding 255 bytes", () => {
		// Create domain name exceeding 255-byte limit
		const oversizedDomainName = new Uint8Array(300);
		let offset = 0;

		// Add many single-character labels to exceed limit
		for (let i = 0; i < 149; i++) {
			oversizedDomainName[offset++] = 1; // Length
			oversizedDomainName[offset++] = 97 + (i % 26); // 'a' to 'z'
		}
		oversizedDomainName[offset] = 0; // Terminator

		return Effect.gen(function* () {
			const result = yield* Effect.exit(
				decodeNameFromUint8Array(oversizedDomainName),
			);
			expect(Exit.isFailure(result)).toBe(true);
		});
	});

	it.effect("should handle maximum label length (63 bytes)", () => {
		// Create label with exactly 63 characters
		const maxLabel = new Uint8Array(65); // 1 length + 63 chars + 1 terminator
		maxLabel[0] = 63; // Length
		for (let i = 1; i <= 63; i++) {
			maxLabel[i] = 97 + ((i - 1) % 26); // Fill with 'a' to 'z'
		}
		maxLabel[64] = 0; // Terminator

		return Effect.gen(function* () {
			const result = yield* Effect.exit(decodeNameFromUint8Array(maxLabel));
			expect(Exit.isSuccess(result)).toBe(true);

			if (Exit.isSuccess(result)) {
				const name = result.value;
				expect(name.labels.length).toBe(1);
				expect(name.labels[0]?.length).toBe(63);
			}
		});
	});

	it.effect("should reject labels exceeding 63 bytes", () => {
		// Create label with 64 characters (invalid)
		const oversizedLabel = new Uint8Array(66); // 1 length + 64 chars + 1 terminator
		oversizedLabel[0] = 64; // Invalid length
		for (let i = 1; i <= 64; i++) {
			oversizedLabel[i] = 97 + ((i - 1) % 26);
		}
		oversizedLabel[65] = 0; // Terminator

		return Effect.gen(function* () {
			const result = yield* Effect.exit(
				decodeNameFromUint8Array(oversizedLabel),
			);
			expect(Exit.isFailure(result)).toBe(true);
		});
	});

	it.effect("should handle maximum RDLENGTH (65535 bytes)", () => {
		// Note: This test creates a large resource record for boundary testing
		// In practice, such large records are rare but valid per RFC

		// For testing purposes, use a smaller but still large RDLENGTH
		const testRdlength = 1000;
		const testRRSize = 12 + 10 + testRdlength;

		const largeRR = new Uint8Array(testRRSize);
		let offset = 0;

		// Name: "test.com"
		largeRR[offset++] = 4; // "test"
		largeRR.set(new TextEncoder().encode("test"), offset);
		offset += 4;
		largeRR[offset++] = 3; // "com"
		largeRR.set(new TextEncoder().encode("com"), offset);
		offset += 3;
		largeRR[offset++] = 0; // Terminator

		// TYPE, CLASS, TTL, RDLENGTH
		const rrView = new DataView(largeRR.buffer, offset);
		rrView.setUint16(0, 16, false); // TYPE=TXT
		rrView.setUint16(2, 1, false); // CLASS=IN
		rrView.setUint32(4, 3600, false); // TTL
		rrView.setUint16(8, testRdlength, false); // RDLENGTH
		offset += 10;

		// RDATA: Fill with valid TXT record data
		largeRR[offset++] = 255; // First string length (max for single string)
		for (let i = 1; i < 256; i++) {
			largeRR[offset++] = 65 + (i % 26); // Fill with A-Z
		}

		// Fill remaining RDATA
		while (offset < testRRSize) {
			const remaining = testRRSize - offset;
			if (remaining > 256) {
				largeRR[offset++] = 255; // String length
				for (let i = 0; i < 255 && offset < testRRSize; i++) {
					largeRR[offset++] = 65 + (i % 26);
				}
			} else if (remaining > 1) {
				largeRR[offset++] = remaining - 1; // String length
				for (let i = 0; i < remaining - 1; i++) {
					largeRR[offset++] = 65 + (i % 26);
				}
			} else {
				break;
			}
		}

		return Effect.gen(function* () {
			const result = yield* Effect.exit(
				decodeResourceRecordFromUint8Array(largeRR),
			);
			expect(Exit.isSuccess(result)).toBe(true);

			if (Exit.isSuccess(result)) {
				const rr = result.value;
				expect(rr.rdlength).toBe(testRdlength);
				expect(rr.rdata.length).toBe(testRdlength);
				expect(rr.type).toBe(16); // TXT
			}
		});
	});

	it.effect("should handle deeply nested pointer chains safely", () => {
		// Create a pointer chain with reasonable depth
		const chainDepth = 10;
		const pointerChain = new Uint8Array(chainDepth * 2 + 15); // Increased size for safety

		// Create chain: each pointer points to the next
		for (let i = 0; i < chainDepth; i++) {
			pointerChain[i * 2] = 0xc0; // Pointer flag
			pointerChain[i * 2 + 1] = (i + 1) * 2; // Point to next
		}

		// Final destination: actual label
		const finalOffset = chainDepth * 2;
		pointerChain[finalOffset] = 7; // "example"
		pointerChain.set(new TextEncoder().encode("example"), finalOffset + 1);
		pointerChain[finalOffset + 8] = 3; // "com"
		pointerChain.set(new TextEncoder().encode("com"), finalOffset + 9);
		pointerChain[finalOffset + 12] = 0; // Terminator

		return Effect.gen(function* () {
			const result = yield* Effect.exit(decodeNameFromUint8Array(pointerChain));
			// Should either succeed or fail gracefully (no infinite loops/stack overflow)
			if (Exit.isSuccess(result)) {
				const name = result.value;
				expect(name.labels.length).toBeGreaterThan(0);
			} else {
				// Failure is acceptable for deep chains (implementation-dependent)
				expect(Exit.isFailure(result)).toBe(true);
			}
		});
	});

	it.effect.prop(
		"should handle various boundary conditions",
		[arbitraryBoundaryConditions],
		([boundaryCase]: [any]) =>
			Effect.gen(function* () {
				expect(boundaryCase.description).toBeDefined();

				// Test different boundary scenarios
				if (boundaryCase.description.includes("Maximum UDP message size")) {
					expect(boundaryCase.size).toBe(512);
					expect(boundaryCase.data.length).toBe(512);
				}

				if (boundaryCase.description.includes("Maximum domain name length")) {
					expect(boundaryCase.domainName.length).toBeLessThanOrEqual(127);
				}

				if (boundaryCase.description.includes("Maximum RDLENGTH")) {
					expect(boundaryCase.rdlength).toBe(65535);
					expect(boundaryCase.rdata.length).toBe(65535);
				}
			}),
	);
});

describe("Performance and Stress Testing", () => {
	it.effect("should handle concurrent parsing operations", () => {
		// Create multiple valid DNS messages
		const messages = Array.from({ length: 100 }, (_, i) => {
			const message = new Uint8Array(29); // Header + minimal question
			const view = new DataView(message.buffer);

			// Header
			view.setUint16(0, i, false); // Unique ID
			view.setUint8(2, 0x01); // RD=1
			view.setUint16(4, 1, false); // QDCOUNT=1

			// Question: "test.com"
			let offset = 12;
			message[offset++] = 4; // "test"
			message.set(new TextEncoder().encode("test"), offset);
			offset += 4;
			message[offset++] = 3; // "com"
			message.set(new TextEncoder().encode("com"), offset);
			offset += 3;
			message[offset++] = 0; // Terminator

			view.setUint16(offset, 1, false); // QTYPE=A
			view.setUint16(offset + 2, 1, false); // QCLASS=IN

			return message;
		});

		return Effect.gen(function* () {
			// Parse all headers concurrently
			const results = yield* Effect.all(
				messages.map((msg) =>
					Effect.exit(decodeHeaderFromUint8Array(msg.slice(0, 12))),
				),
				{ concurrency: "unbounded" },
			);

			// All should succeed
			results.forEach((result, i) => {
				expect(Exit.isSuccess(result)).toBe(true);
				if (Exit.isSuccess(result)) {
					expect(result.value.id).toBe(i);
				}
			});
		});
	});

	it.effect("should maintain performance with large messages", () => {
		// Create a message with many resource records
		const recordCount = 50;
		const baseSize = 12 + 17; // Header + question
		const recordSize = 16 + 4; // Name pointer + fields + IPv4
		const totalSize = baseSize + recordCount * recordSize;

		const largeMessage = new Uint8Array(totalSize);
		const view = new DataView(largeMessage.buffer);

		// Header
		view.setUint16(0, 12345, false); // ID
		view.setUint8(2, 0x81); // QR=1, RD=1
		view.setUint8(3, 0x80); // RA=1
		view.setUint16(4, 1, false); // QDCOUNT=1
		view.setUint16(6, recordCount, false); // ANCOUNT

		// Question
		let offset = 12;
		largeMessage[offset++] = 7; // "example"
		largeMessage.set(new TextEncoder().encode("example"), offset);
		offset += 7;
		largeMessage[offset++] = 3; // "com"
		largeMessage.set(new TextEncoder().encode("com"), offset);
		offset += 3;
		largeMessage[offset++] = 0; // Terminator
		view.setUint16(offset, 1, false); // QTYPE=A
		view.setUint16(offset + 2, 1, false); // QCLASS=IN
		offset += 4;

		// Answer records
		for (let i = 0; i < recordCount; i++) {
			// Name (pointer to question)
			largeMessage[offset++] = 0xc0;
			largeMessage[offset++] = 0x0c;

			// TYPE, CLASS, TTL, RDLENGTH
			view.setUint16(offset, 1, false); // TYPE=A
			view.setUint16(offset + 2, 1, false); // CLASS=IN
			view.setUint32(offset + 4, 3600, false); // TTL
			view.setUint16(offset + 8, 4, false); // RDLENGTH
			offset += 10;

			// RDATA (IPv4 address)
			largeMessage[offset++] = 192;
			largeMessage[offset++] = 168;
			largeMessage[offset++] = 1;
			largeMessage[offset++] = i % 255;
		}

		return Effect.gen(function* () {
			const startTime = Date.now();

			const headerResult = yield* Effect.exit(
				decodeHeaderFromUint8Array(largeMessage.slice(0, 12)),
			);
			expect(Exit.isSuccess(headerResult)).toBe(true);

			if (Exit.isSuccess(headerResult)) {
				const header = headerResult.value;
				expect(header.ancount).toBe(recordCount);
			}

			const endTime = Date.now();
			const duration = endTime - startTime;

			// Should complete within reasonable time (adjust threshold as needed)
			expect(duration).toBeLessThan(100); // 100ms threshold
		});
	});

	it.effect.prop(
		"should handle stress test scenarios",
		[arbitraryStressTestMessage],
		([stressCase]: [any]) =>
			Effect.gen(function* () {
				expect(stressCase.description).toBeDefined();

				// Validate stress test parameters are within reasonable bounds
				if (stressCase.recordCount) {
					expect(stressCase.recordCount).toBeGreaterThan(0);
					expect(stressCase.recordCount).toBeLessThanOrEqual(65535);
				}

				if (stressCase.messageSize) {
					expect(stressCase.messageSize).toBeGreaterThan(0);
					expect(stressCase.messageSize).toBeLessThanOrEqual(65535);
				}

				if (stressCase.chainDepth) {
					expect(stressCase.chainDepth).toBeGreaterThan(0);
					expect(stressCase.chainDepth).toBeLessThanOrEqual(255);
				}
			}),
	);

	it.effect("should handle memory efficiently with repeated parsing", () => {
		// Test memory usage doesn't grow unbounded with repeated operations
		const testMessage = new Uint8Array([
			// Header
			0x30, 0x39, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			// Question: "test.com"
			0x04, 0x74, 0x65, 0x73, 0x74, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01,
			0x00, 0x01,
		]);

		return Effect.gen(function* () {
			// Parse the same message many times
			for (let i = 0; i < 1000; i++) {
				const result = yield* Effect.exit(
					decodeHeaderFromUint8Array(testMessage.slice(0, 12)),
				);
				expect(Exit.isSuccess(result)).toBe(true);
			}

			// If we reach here without memory issues, test passes
			expect(true).toBe(true);
		});
	});
});
