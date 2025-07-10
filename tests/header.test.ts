import { describe, expect, it } from "@effect/vitest";
import { Effect, Exit } from "effect";
import {
	decodeHeaderFromUint8Array,
	encodeHeaderToUint8Array,
} from "../src/header";
import {
	arbitraryValidDnsHeaderUint8Array,
	arbitraryInvalidDnsHeaderUint8Array,
} from "./arbitraries";

describe("header", () => {
	it.effect.prop(
		"successfully decodes valid RFC-compliant headers",
		[arbitraryValidDnsHeaderUint8Array],
		([uint8Array]) =>
			Effect.gen(function* () {
				const result = yield* Effect.exit(
					decodeHeaderFromUint8Array(uint8Array),
				);
				expect(Exit.isSuccess(result)).toBe(true);

				if (Exit.isSuccess(result)) {
					const header = result.value;
					// Validate RFC compliance
					expect(header.z).toBe(0); // Z field must be zero
					expect(header.opcode).toBeLessThanOrEqual(15);
					expect(header.rcode).toBeLessThanOrEqual(15);
				}
			}),
	);

	it.effect.prop(
		"rejects headers with RFC violations",
		[arbitraryInvalidDnsHeaderUint8Array],
		([uint8Array]) =>
			Effect.gen(function* () {
				const result = yield* Effect.exit(
					decodeHeaderFromUint8Array(uint8Array),
				);
				// RFC 1035 requires rejection of:
				// - Non-zero Z field
				// - Reserved opcodes 3-15
				// - Reserved rcodes 6-15
				expect(Exit.isFailure(result)).toBe(true);
			}),
	);

	it.effect("fails to decode header with non-zero Z field", () =>
		Effect.gen(function* () {
			// RFC 1035: "Reserved for future use. Must be zero in all queries and responses."
			const headerBytes = new Uint8Array(12);
			const dataView = new DataView(headerBytes.buffer);
			dataView.setUint8(3, 0x70); // Set Z bits to non-zero (bits 4-6)

			const result = yield* Effect.exit(
				decodeHeaderFromUint8Array(headerBytes),
			);
			expect(Exit.isFailure(result)).toBe(true);
		}),
	);

	it.effect("validates reserved opcode values", () =>
		Effect.gen(function* () {
			// RFC 1035: opcodes 3-15 are "reserved for future use"
			const reservedOpcodes = [3, 4, 5, 15];

			for (const opcode of reservedOpcodes) {
				const headerBytes = new Uint8Array(12);
				const dataView = new DataView(headerBytes.buffer);
				dataView.setUint8(2, (opcode & 0x0f) << 3);

				const result = yield* Effect.exit(
					decodeHeaderFromUint8Array(headerBytes),
				);
				expect(Exit.isFailure(result)).toBe(true);
			}
		}),
	);

	it.effect("validates reserved rcode values", () =>
		Effect.gen(function* () {
			// RFC 1035: rcodes 6-15 are "Reserved for future use"
			const reservedRcodes = [6, 7, 8, 15];

			for (const rcode of reservedRcodes) {
				const headerBytes = new Uint8Array(12);
				const dataView = new DataView(headerBytes.buffer);
				dataView.setUint8(3, rcode & 0x0f);

				const result = yield* Effect.exit(
					decodeHeaderFromUint8Array(headerBytes),
				);
				expect(Exit.isFailure(result)).toBe(true);
			}
		}),
	);

	it.effect("validates semantic consistency between QR and other fields", () =>
		Effect.gen(function* () {
			// RFC 1035: queries (QR=0) cannot be authoritative (AA=1)
			const queryHeader = new Uint8Array(12);
			const dataView = new DataView(queryHeader.buffer);
			dataView.setUint8(2, 0x04); // QR=0, AA=1

			const result = yield* Effect.exit(
				decodeHeaderFromUint8Array(queryHeader),
			);
			expect(Exit.isFailure(result)).toBe(true);
		}),
	);

	it.effect.prop(
		"roundtrip encoding preserves all fields",
		[arbitraryValidDnsHeaderUint8Array],
		([uint8Array]) =>
			Effect.gen(function* () {
				const decoded = yield* decodeHeaderFromUint8Array(uint8Array);
				const encoded = yield* encodeHeaderToUint8Array(decoded);
				expect(Array.from(encoded)).toEqual(Array.from(uint8Array));
			}),
	);

	it.effect("fails on invalid length", () =>
		Effect.gen(function* () {
			const invalidLengths = [0, 11, 13, 24];

			for (const length of invalidLengths) {
				const headerBytes = new Uint8Array(length);
				const result = yield* Effect.exit(
					decodeHeaderFromUint8Array(headerBytes),
				);
				expect(Exit.isFailure(result)).toBe(true);
			}
		}),
	);

	it.effect("validates header byte order consistency", () =>
		Effect.gen(function* () {
			// Test that all 16-bit and 32-bit fields use network byte order (big-endian)
			const header = {
				id: 0x1234,
				qr: 1,
				opcode: 0,
				aa: 1,
				tc: 0,
				rd: 1,
				ra: 1,
				z: 0,
				rcode: 0,
				qdcount: 0x5678,
				ancount: 0x9abc,
				nscount: 0xdef0,
				arcount: 0x1357,
			} as const;

			const encoded = yield* encodeHeaderToUint8Array(header);

			// Verify byte order manually - should be big-endian (network byte order)
			expect(encoded[0]).toBe(0x12); // High byte of ID
			expect(encoded[1]).toBe(0x34); // Low byte of ID
			expect(encoded[4]).toBe(0x56); // High byte of QDCOUNT
			expect(encoded[5]).toBe(0x78); // Low byte of QDCOUNT
			expect(encoded[6]).toBe(0x9a); // High byte of ANCOUNT
			expect(encoded[7]).toBe(0xbc); // Low byte of ANCOUNT
			expect(encoded[8]).toBe(0xde); // High byte of NSCOUNT
			expect(encoded[9]).toBe(0xf0); // Low byte of NSCOUNT
			expect(encoded[10]).toBe(0x13); // High byte of ARCOUNT
			expect(encoded[11]).toBe(0x57); // Low byte of ARCOUNT
		}),
	);
});

