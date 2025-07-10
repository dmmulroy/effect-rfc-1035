import { describe, expect, it } from "@effect/vitest";
import { Effect, Exit } from "effect";
import {
	decodeResourceRecordFromUint8Array,
	encodeResourceRecord,
	RRTypeNameToRRType,
} from "../src/resource-record";
import { arbitraryValidResourceRecordUint8Array } from "./arbitraries";

describe("resource record", () => {
	it.effect.prop(
		"successfully decodes valid RFC-compliant resource records",
		[arbitraryValidResourceRecordUint8Array],
		([uint8Array]) =>
			Effect.gen(function* () {
				const result = yield* Effect.exit(
					decodeResourceRecordFromUint8Array(uint8Array),
				);
				expect(Exit.isSuccess(result)).toBe(true);

				if (Exit.isSuccess(result)) {
					const record = result.value;
					// Validate RFC compliance
					expect(record.ttl).toBeGreaterThanOrEqual(0);
					expect(record.ttl).toBeLessThanOrEqual(2147483647); // 31-bit max
					expect(record.rdata.length).toBe(record.rdlength);
				}
			}),
	);

	it.effect("validates TTL special semantics", () =>
		Effect.gen(function* () {
			// TTL=0 has special meaning (no caching)
			const record = {
				name: {
					labels: [new Uint8Array([116, 101, 115, 116])],
					encodedByteLength: 6,
				}, // "test"
				type: RRTypeNameToRRType.A,
				class: 1,
				ttl: 0,
				rdlength: 4,
				rdata: new Uint8Array([192, 0, 2, 1]),
			};

			const encoded = yield* encodeResourceRecord(record);
			const decoded = yield* decodeResourceRecordFromUint8Array(encoded);
			expect(decoded.ttl).toBe(0);
		}),
	);

	it.effect("validates RDATA format for A records", () =>
		Effect.gen(function* () {
			// A records must have exactly 4 bytes of RDATA per RFC 1035
			const validARecord = {
				name: {
					labels: [new Uint8Array([116, 101, 115, 116])],
					encodedByteLength: 6,
				},
				type: RRTypeNameToRRType.A,
				class: 1,
				ttl: 3600,
				rdlength: 4,
				rdata: new Uint8Array([192, 0, 2, 1]), // Valid IPv4
			};

			const encoded = yield* encodeResourceRecord(validARecord);
			const decoded = yield* decodeResourceRecordFromUint8Array(encoded);
			expect(decoded.rdlength).toBe(4);
			expect(decoded.rdata.length).toBe(4);

			// Invalid A record with wrong RDLENGTH
			const invalidARecord = {
				...validARecord,
				rdlength: 5,
				rdata: new Uint8Array([192, 0, 2, 1, 0]), // Wrong length
			};

			const result = yield* Effect.exit(encodeResourceRecord(invalidARecord));
			expect(Exit.isFailure(result)).toBe(true);
		}),
	);

	it.effect("validates RDATA format for MX records", () =>
		Effect.gen(function* () {
			// MX records must have preference + domain name
			const validMXRecord = {
				name: {
					labels: [new Uint8Array([116, 101, 115, 116])],
					encodedByteLength: 6,
				},
				type: RRTypeNameToRRType.MX,
				class: 1,
				ttl: 3600,
				rdlength: 8, // 2 bytes preference + 6 bytes for "mail" + terminator
				rdata: new Uint8Array([0, 10, 4, 109, 97, 105, 108, 0]), // preference 10, "mail"
			};

			const encoded = yield* encodeResourceRecord(validMXRecord);
			const decoded = yield* decodeResourceRecordFromUint8Array(encoded);
			expect(decoded.rdlength).toBe(8);
			expect(decoded.rdata.length).toBe(8);
		}),
	);

	it.effect("correctly validates TTL boundary", () =>
		Effect.gen(function* () {
			// TTL with high bit set (32-bit value > 31-bit max)
			const recordBytes = new Uint8Array([
				4,
				116,
				101,
				115,
				116, // "test"
				0, // terminator
				0,
				1, // TYPE: A
				0,
				1, // CLASS: IN
				0x80,
				0x00,
				0x00,
				0x00, // TTL with high bit set (2147483648 > 2147483647)
				0,
				4, // RDLENGTH: 4
				192,
				0,
				2,
				1, // RDATA
			]);

			const result = yield* Effect.exit(
				decodeResourceRecordFromUint8Array(recordBytes),
			);
			// This should fail and correctly does - TTL validation works
			expect(Exit.isFailure(result)).toBe(true);

			// Test the boundary case: exactly 2^31-1 should pass
			const validTtlBytes = new Uint8Array([
				4,
				116,
				101,
				115,
				116, // "test"
				0, // terminator
				0,
				1, // TYPE: A
				0,
				1, // CLASS: IN
				0x7f,
				0xff,
				0xff,
				0xff, // TTL = 2147483647 (max valid)
				0,
				4, // RDLENGTH: 4
				192,
				0,
				2,
				1, // RDATA
			]);

			const validResult = yield* Effect.exit(
				decodeResourceRecordFromUint8Array(validTtlBytes),
			);
			expect(Exit.isSuccess(validResult)).toBe(true);
		}),
	);

	it.effect("validates RDLENGTH consistency", () =>
		Effect.gen(function* () {
			// RDLENGTH must match actual RDATA length
			const recordBytes = new Uint8Array([
				4,
				116,
				101,
				115,
				116, // "test"
				0, // terminator
				0,
				1, // TYPE: A
				0,
				1, // CLASS: IN
				0,
				0,
				0,
				60, // TTL: 60
				0,
				5, // RDLENGTH: 5 (but only 4 bytes follow)
				192,
				0,
				2,
				1, // RDATA (4 bytes, not 5)
			]);

			const result = yield* Effect.exit(
				decodeResourceRecordFromUint8Array(recordBytes),
			);
			expect(Exit.isFailure(result)).toBe(true);
		}),
	);

	it.effect.prop(
		"roundtrip encoding preserves valid resource records",
		[arbitraryValidResourceRecordUint8Array],
		([uint8Array]) =>
			Effect.gen(function* () {
				const decoded = yield* decodeResourceRecordFromUint8Array(uint8Array);
				const encoded = yield* encodeResourceRecord(decoded);
				expect(Array.from(encoded)).toEqual(Array.from(uint8Array));
			}),
	);

	it.effect("validates record type specific constraints", () =>
		Effect.gen(function* () {
			// A records must have exactly 4 bytes of RDATA per RFC 1035
			const invalidARecord = {
				name: {
					labels: [new Uint8Array([116, 101, 115, 116])],
					encodedByteLength: 6,
				},
				type: RRTypeNameToRRType.A,
				class: 1,
				ttl: 3600,
				rdlength: 5, // Invalid for A record
				rdata: new Uint8Array([192, 0, 2, 1, 0]),
			};

			const result = yield* Effect.exit(encodeResourceRecord(invalidARecord));
			expect(Exit.isFailure(result)).toBe(true);

			// NULL records can have any RDLENGTH per RFC 1035
			const validNullRecord = {
				name: {
					labels: [new Uint8Array([116, 101, 115, 116])],
					encodedByteLength: 6,
				},
				type: RRTypeNameToRRType.NULL,
				class: 1,
				ttl: 3600,
				rdlength: 10,
				rdata: new Uint8Array(10).fill(0),
			};

			const validResult = yield* Effect.exit(
				encodeResourceRecord(validNullRecord),
			);
			expect(Exit.isSuccess(validResult)).toBe(true);
		}),
	);

	describe("boundary conditions and edge cases", () => {
		it.effect("validates Name usage in ResourceRecord context", () =>
			Effect.gen(function* () {
				// Valid Name should work in ResourceRecord
				const validName = {
					labels: [
						new Uint8Array([109, 97, 105, 108]), // "mail"
						new Uint8Array([101, 120, 97, 109, 112, 108, 101]), // "example"
						new Uint8Array([99, 111, 109]), // "com"
					],
					encodedByteLength: 18,
				};

				const record = {
					name: validName,
					type: RRTypeNameToRRType.A,
					class: 1,
					ttl: 3600,
					rdlength: 4,
					rdata: new Uint8Array([192, 0, 2, 1]),
				};

				const encoded = yield* encodeResourceRecord(record);
				const decoded = yield* decodeResourceRecordFromUint8Array(encoded);
				expect(decoded.name.labels.length).toBe(3);

				// Invalid Name should fail in ResourceRecord
				const invalidName = {
					labels: [
						new Uint8Array([109, 97, 105, 108, 45]), // "mail-" (ends with hyphen)
						new Uint8Array([101, 120, 97, 109, 112, 108, 101]), // "example"
						new Uint8Array([99, 111, 109]), // "com"
					],
					encodedByteLength: 19,
				};

				const invalidRecord = {
					name: invalidName,
					type: RRTypeNameToRRType.A,
					class: 1,
					ttl: 3600,
					rdlength: 4,
					rdata: new Uint8Array([192, 0, 2, 1]),
				};

				const result = yield* Effect.exit(encodeResourceRecord(invalidRecord));
				expect(Exit.isFailure(result)).toBe(true);
			}),
		);
	});
});
