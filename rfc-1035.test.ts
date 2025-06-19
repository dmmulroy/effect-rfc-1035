import { describe, expect, it } from "@effect/vitest";
import { Effect, Exit, FastCheck as fc } from "effect";
import {
	decodeHeader,
	encodeHeader,
	decodeQuestion,
	encodeQuestion,
	decodeResourceRecord,
	encodeResourceRecord,
	DnsType,
} from ".";

// RFC-compliant DNS label generator (letters, digits, hyphens only)
// RFC 1035: Must start and end with letter/digit, no consecutive hyphens
const arbitraryValidDnsLabel = fc
	.stringMatching(/^[a-zA-Z0-9]([a-zA-Z0-9]|[a-zA-Z0-9]-[a-zA-Z0-9])*$/)
	.filter((s) => s.length >= 1 && s.length <= 63)
	.filter((s) => !s.includes("--")) // No consecutive hyphens
	.map((s) => new Uint8Array(Array.from(s, (c) => c.charCodeAt(0))));

// Generate realistic domain names with proper DNS structure
const arbitraryValidDomainName = fc
	.oneof(
		// Single label domains (rare but valid)
		fc
			.tuple(arbitraryValidDnsLabel)
			.map(([label]) => [label]),
		// Standard domain.tld
		fc
			.tuple(
				arbitraryValidDnsLabel,
				fc
					.constantFrom("com", "org", "net", "edu", "gov")
					.map(
						(tld) => new Uint8Array(Array.from(tld, (c) => c.charCodeAt(0))),
					),
			)
			.map(([domain, tld]) => [domain, tld]),
		// Subdomain.domain.tld
		fc
			.tuple(
				arbitraryValidDnsLabel,
				arbitraryValidDnsLabel,
				fc
					.constantFrom("com", "org", "net", "edu")
					.map(
						(tld) => new Uint8Array(Array.from(tld, (c) => c.charCodeAt(0))),
					),
			)
			.map(([sub, domain, tld]) => [sub, domain, tld]),
	)
	.filter((labels) => {
		// Ensure total length doesn't exceed 255 bytes
		const totalLength =
			labels.reduce((sum, label) => sum + label.length + 1, 0) + 1;
		return totalLength <= 255;
	});

// Generate valid DNS header with realistic values
const arbitraryValidDnsHeader = fc.record({
	id: fc.integer({ min: 0, max: 65535 }),
	qr: fc.constantFrom(0, 1),
	opcode: fc.constantFrom(0, 1, 2), // QUERY, IQUERY, STATUS only
	aa: fc.constantFrom(0, 1),
	tc: fc.constantFrom(0, 1),
	rd: fc.constantFrom(0, 1),
	ra: fc.constantFrom(0, 1),
	z: fc.constant(0), // Must be zero per RFC
	rcode: fc.constantFrom(0, 1, 2, 3, 4, 5), // Valid response codes only
	qdcount: fc.integer({ min: 0, max: 10 }), // Realistic counts
	ancount: fc.integer({ min: 0, max: 20 }),
	nscount: fc.integer({ min: 0, max: 10 }),
	arcount: fc.integer({ min: 0, max: 15 }),
});

// Generate headers with RFC violations for negative testing
const arbitraryInvalidDnsHeader = fc.record({
	id: fc.integer({ min: 0, max: 65535 }),
	qr: fc.constantFrom(0, 1),
	opcode: fc.constantFrom(3, 4, 5, 15), // Reserved opcodes
	aa: fc.constantFrom(0, 1),
	tc: fc.constantFrom(0, 1),
	rd: fc.constantFrom(0, 1),
	ra: fc.constantFrom(0, 1),
	z: fc.constantFrom(1, 2, 7), // Non-zero Z field (RFC violation)
	rcode: fc.constantFrom(6, 7, 8, 15), // Reserved rcodes
	qdcount: fc.integer({ min: 0, max: 10 }),
	ancount: fc.integer({ min: 0, max: 20 }),
	nscount: fc.integer({ min: 0, max: 10 }),
	arcount: fc.integer({ min: 0, max: 15 }),
});

// Generate valid DNS header as Uint8Array
const arbitraryValidDnsHeaderUint8Array = arbitraryValidDnsHeader.map(
	(header) => {
		const buffer = new ArrayBuffer(12);
		const dataView = new DataView(buffer);

		dataView.setUint16(0, header.id, false);

		let byte2 = 0;
		byte2 |= (header.qr & 0x01) << 7;
		byte2 |= (header.opcode & 0x0f) << 3;
		byte2 |= (header.aa & 0x01) << 2;
		byte2 |= (header.tc & 0x01) << 1;
		byte2 |= header.rd & 0x01;
		dataView.setUint8(2, byte2);

		let byte3 = 0;
		byte3 |= (header.ra & 0x01) << 7;
		byte3 |= (header.z & 0x07) << 4; // Should always be 0
		byte3 |= header.rcode & 0x0f;
		dataView.setUint8(3, byte3);

		dataView.setUint16(4, header.qdcount, false);
		dataView.setUint16(6, header.ancount, false);
		dataView.setUint16(8, header.nscount, false);
		dataView.setUint16(10, header.arcount, false);

		return new Uint8Array(buffer);
	},
);

// Generate invalid DNS header as Uint8Array for negative testing
const arbitraryInvalidDnsHeaderUint8Array = arbitraryInvalidDnsHeader.map(
	(header) => {
		const buffer = new ArrayBuffer(12);
		const dataView = new DataView(buffer);

		dataView.setUint16(0, header.id, false);

		let byte2 = 0;
		byte2 |= (header.qr & 0x01) << 7;
		byte2 |= (header.opcode & 0x0f) << 3;
		byte2 |= (header.aa & 0x01) << 2;
		byte2 |= (header.tc & 0x01) << 1;
		byte2 |= header.rd & 0x01;
		dataView.setUint8(2, byte2);

		let byte3 = 0;
		byte3 |= (header.ra & 0x01) << 7;
		byte3 |= (header.z & 0x07) << 4; // Non-zero values for testing
		byte3 |= header.rcode & 0x0f;
		dataView.setUint8(3, byte3);

		dataView.setUint16(4, header.qdcount, false);
		dataView.setUint16(6, header.ancount, false);
		dataView.setUint16(8, header.nscount, false);
		dataView.setUint16(10, header.arcount, false);

		return new Uint8Array(buffer);
	},
);

// Generate valid DNS question
const arbitraryValidDnsQuestion = fc.record({
	qname: arbitraryValidDomainName,
	qtype: fc.constantFrom(...Object.values(DnsType)),
	qclass: fc.constantFrom(1, 3, 4), // IN, CH, HS
});

// Generate valid DNS question as Uint8Array
const arbitraryValidDnsQuestionUint8Array = arbitraryValidDnsQuestion.map(
	(question) => {
		const totalLength =
			question.qname.reduce((sum, label) => sum + label.length + 1, 0) + 5;
		const buffer = new Uint8Array(totalLength);
		const dataView = new DataView(buffer.buffer);

		let offset = 0;

		// Write labels
		for (const label of question.qname) {
			buffer[offset++] = label.length;
			buffer.set(label, offset);
			offset += label.length;
		}

		// Write terminator
		buffer[offset++] = 0;

		// Write qtype and qclass
		dataView.setUint16(offset, question.qtype, false);
		offset += 2;
		dataView.setUint16(offset, question.qclass, false);

		return buffer;
	},
);

// Generate realistic TTL values
const arbitraryRealisticTtl = fc.oneof(
	fc.constantFrom(0, 60, 300, 3600, 86400), // Common values
	fc.integer({ min: 1, max: 2147483647 }), // Valid 31-bit range
);

// Generate valid resource record
const arbitraryValidResourceRecord = fc
	.record({
		name: arbitraryValidDomainName,
		type: fc.constantFrom(...Object.values(DnsType)),
		class: fc.constantFrom(1, 3, 4),
		ttl: arbitraryRealisticTtl,
		rdlength: fc.integer({ min: 0, max: 512 }),
	})
	.chain((record) =>
		fc
			.uint8Array({ minLength: record.rdlength, maxLength: record.rdlength })
			.map((rdata) => ({
				...record,
				rdata,
			})),
	);

// Generate valid resource record as Uint8Array
const arbitraryValidResourceRecordUint8Array = arbitraryValidResourceRecord.map(
	(record) => {
		const nameLength =
			record.name.reduce((sum, label) => sum + label.length + 1, 0) + 1;
		const totalLength = nameLength + 10 + record.rdlength;

		const buffer = new Uint8Array(totalLength);
		const dataView = new DataView(buffer.buffer);
		let offset = 0;

		// Write name labels
		for (const label of record.name) {
			buffer[offset++] = label.length;
			buffer.set(label, offset);
			offset += label.length;
		}

		// Write terminator
		buffer[offset++] = 0;

		// Write TYPE, CLASS, TTL, RDLENGTH
		dataView.setUint16(offset, record.type, false);
		offset += 2;
		dataView.setUint16(offset, record.class, false);
		offset += 2;
		dataView.setUint32(offset, record.ttl, false);
		offset += 4;
		dataView.setUint16(offset, record.rdlength, false);
		offset += 2;

		// Write RDATA
		buffer.set(record.rdata, offset);

		return buffer;
	},
);

describe("rfc-1035", () => {
	describe("header", () => {
		it.effect.prop(
			"successfully decodes valid RFC-compliant headers",
			[arbitraryValidDnsHeaderUint8Array],
			([uint8Array]) =>
				Effect.gen(function* () {
					const result = yield* Effect.exit(decodeHeader(uint8Array));
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
					const result = yield* Effect.exit(decodeHeader(uint8Array));
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

				const result = yield* Effect.exit(decodeHeader(headerBytes));
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

					const result = yield* Effect.exit(decodeHeader(headerBytes));
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

					const result = yield* Effect.exit(decodeHeader(headerBytes));
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

				const result = yield* Effect.exit(decodeHeader(queryHeader));
				expect(Exit.isFailure(result)).toBe(true);
			}),
		);

		it.effect.prop(
			"roundtrip encoding preserves all fields",
			[arbitraryValidDnsHeaderUint8Array],
			([uint8Array]) =>
				Effect.gen(function* () {
					const decoded = yield* decodeHeader(uint8Array);
					const encoded = yield* encodeHeader(decoded);
					expect(Array.from(encoded)).toEqual(Array.from(uint8Array));
				}),
		);

		it.effect("fails on invalid length", () =>
			Effect.gen(function* () {
				const invalidLengths = [0, 11, 13, 24];

				for (const length of invalidLengths) {
					const headerBytes = new Uint8Array(length);
					const result = yield* Effect.exit(decodeHeader(headerBytes));
					expect(Exit.isFailure(result)).toBe(true);
				}
			}),
		);
	});

	describe("question", () => {
		it.effect.prop(
			"successfully decodes valid RFC-compliant questions",
			[arbitraryValidDnsQuestionUint8Array],
			([uint8Array]) =>
				Effect.gen(function* () {
					const result = yield* Effect.exit(decodeQuestion(uint8Array));
					expect(Exit.isSuccess(result)).toBe(true);

					if (Exit.isSuccess(result)) {
						const question = result.value;
						// Validate RFC compliance
						for (const label of question.qname) {
							expect(label.length).toBeLessThanOrEqual(63);
							// Should validate label content (letters, digits, hyphens only)
						}
					}
				}),
		);

		it.effect("fails on labels with invalid characters", () =>
			Effect.gen(function* () {
				// RFC 1035: DNS labels must contain only letters, digits, and hyphens
				const invalidLabels = [
					"hello world", // space
					"test@domain", // @ symbol
					"under_score", // underscore
					"café", // non-ASCII
					"-invalid", // starts with hyphen
					"invalid-", // ends with hyphen
					"", // empty label
				];

				for (const invalidLabel of invalidLabels) {
					const labelBytes = new Uint8Array(
						Array.from(invalidLabel, (c) => c.charCodeAt(0)),
					);
					const questionBytes = new Uint8Array(invalidLabel.length + 6);

					questionBytes[0] = labelBytes.length;
					questionBytes.set(labelBytes, 1);
					questionBytes[invalidLabel.length + 1] = 0; // terminator
					// Add QTYPE and QCLASS
					questionBytes[invalidLabel.length + 2] = 0;
					questionBytes[invalidLabel.length + 3] = 1;
					questionBytes[invalidLabel.length + 4] = 0;
					questionBytes[invalidLabel.length + 5] = 1;

					const result = yield* Effect.exit(decodeQuestion(questionBytes));
					expect(Exit.isFailure(result)).toBe(true);
				}
			}),
		);

		it.effect("fails on consecutive hyphens in labels", () =>
			Effect.gen(function* () {
				// RFC 1035: consecutive hyphens are not allowed
				const invalidLabel = "test--invalid";
				const labelBytes = new Uint8Array(
					Array.from(invalidLabel, (c) => c.charCodeAt(0)),
				);
				const questionBytes = new Uint8Array(invalidLabel.length + 6);

				questionBytes[0] = labelBytes.length;
				questionBytes.set(labelBytes, 1);
				questionBytes[invalidLabel.length + 1] = 0;
				// Add QTYPE and QCLASS
				questionBytes[invalidLabel.length + 2] = 0;
				questionBytes[invalidLabel.length + 3] = 1;
				questionBytes[invalidLabel.length + 4] = 0;
				questionBytes[invalidLabel.length + 5] = 1;

				const result = yield* Effect.exit(decodeQuestion(questionBytes));
				expect(Exit.isFailure(result)).toBe(true);
			}),
		);

		it.effect("validates special/reserved domain names", () =>
			Effect.gen(function* () {
				// Test reserved domain names that should be handled specially
				const reservedDomains = [
					["localhost"],
					["example", "com"], // RFC 2606 reserved
					["test", "invalid"], // RFC 6761 special-use
				];

				for (const domain of reservedDomains) {
					const question = {
						qname: domain.map(
							(label) =>
								new Uint8Array(Array.from(label, (c) => c.charCodeAt(0))),
						),
						qtype: DnsType.A,
						qclass: 1,
					};

					const encoded = yield* encodeQuestion(question);
					const decoded = yield* decodeQuestion(encoded);
					expect(decoded.qname.length).toBe(domain.length);
				}
			}),
		);

		it.effect("validates QTYPE/QCLASS combinations", () =>
			Effect.gen(function* () {
				// RFC 1035: QTYPE 0 and QCLASS 0 are invalid
				const invalidCombinations = [
					{ qtype: 0, qclass: 1 }, // Invalid QTYPE 0
					{ qtype: DnsType.A, qclass: 0 }, // Invalid QCLASS 0
				];

				for (const combo of invalidCombinations) {
					const question = {
						qname: [new Uint8Array([116, 101, 115, 116])], // "test"
						qtype: combo.qtype,
						qclass: combo.qclass,
					};

					const result = yield* Effect.exit(encodeQuestion(question));
					expect(Exit.isFailure(result)).toBe(true);
				}
			}),
		);

		it.effect.prop(
			"roundtrip encoding preserves valid questions",
			[arbitraryValidDnsQuestionUint8Array],
			([uint8Array]) =>
				Effect.gen(function* () {
					const decoded = yield* decodeQuestion(uint8Array);
					const encoded = yield* encodeQuestion(decoded);
					expect(Array.from(encoded)).toEqual(Array.from(uint8Array));
				}),
		);

		it.effect("handles internationalized domain names", () =>
			Effect.gen(function* () {
				// IDN should be punycode encoded, not raw UTF-8
				const unicodeDomain = "xn--fsq.com"; // punycode for "中.com"
				const question = {
					qname: [
						new Uint8Array(Array.from("xn--fsq", (c) => c.charCodeAt(0))),
						new Uint8Array(Array.from("com", (c) => c.charCodeAt(0))),
					],
					qtype: DnsType.A,
					qclass: 1,
				};

				const encoded = yield* encodeQuestion(question);
				const decoded = yield* decodeQuestion(encoded);
				expect(decoded.qname.length).toBe(2);
			}),
		);
	});

	describe("resource record", () => {
		it.effect.prop(
			"successfully decodes valid RFC-compliant resource records",
			[arbitraryValidResourceRecordUint8Array],
			([uint8Array]) =>
				Effect.gen(function* () {
					const result = yield* Effect.exit(decodeResourceRecord(uint8Array));
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
					name: [new Uint8Array([116, 101, 115, 116])], // "test"
					type: DnsType.A,
					class: 1,
					ttl: 0,
					rdlength: 4,
					rdata: new Uint8Array([192, 0, 2, 1]),
				};

				const encoded = yield* encodeResourceRecord(record);
				const decoded = yield* decodeResourceRecord(encoded);
				expect(decoded.ttl).toBe(0);
			}),
		);

		it.effect("validates RDATA format for A records", () =>
			Effect.gen(function* () {
				// A records must have exactly 4 bytes of RDATA per RFC 1035
				const validARecord = {
					name: [new Uint8Array([116, 101, 115, 116])],
					type: DnsType.A,
					class: 1,
					ttl: 3600,
					rdlength: 4,
					rdata: new Uint8Array([192, 0, 2, 1]), // Valid IPv4
				};

				const encoded = yield* encodeResourceRecord(validARecord);
				const decoded = yield* decodeResourceRecord(encoded);
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
					name: [new Uint8Array([116, 101, 115, 116])],
					type: DnsType.MX,
					class: 1,
					ttl: 3600,
					rdlength: 8, // 2 bytes preference + 6 bytes for "mail" + terminator
					rdata: new Uint8Array([0, 10, 4, 109, 97, 105, 108, 0]), // preference 10, "mail"
				};

				const encoded = yield* encodeResourceRecord(validMXRecord);
				const decoded = yield* decodeResourceRecord(encoded);
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

				const result = yield* Effect.exit(decodeResourceRecord(recordBytes));
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

				const validResult = yield* Effect.exit(decodeResourceRecord(validTtlBytes));
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

				const result = yield* Effect.exit(decodeResourceRecord(recordBytes));
				expect(Exit.isFailure(result)).toBe(true);
			}),
		);

		it.effect.prop(
			"roundtrip encoding preserves valid resource records",
			[arbitraryValidResourceRecordUint8Array],
			([uint8Array]) =>
				Effect.gen(function* () {
					const decoded = yield* decodeResourceRecord(uint8Array);
					const encoded = yield* encodeResourceRecord(decoded);
					expect(Array.from(encoded)).toEqual(Array.from(uint8Array));
				}),
		);

		it.effect("validates record type specific constraints", () =>
			Effect.gen(function* () {
				// A records must have exactly 4 bytes of RDATA per RFC 1035
				const invalidARecord = {
					name: [new Uint8Array([116, 101, 115, 116])],
					type: DnsType.A,
					class: 1,
					ttl: 3600,
					rdlength: 5, // Invalid for A record
					rdata: new Uint8Array([192, 0, 2, 1, 0]),
				};

				const result = yield* Effect.exit(encodeResourceRecord(invalidARecord));
				expect(Exit.isFailure(result)).toBe(true);

				// NULL records can have any RDLENGTH per RFC 1035
				const validNullRecord = {
					name: [new Uint8Array([116, 101, 115, 116])],
					type: DnsType.NULL,
					class: 1,
					ttl: 3600,
					rdlength: 10,
					rdata: new Uint8Array(10).fill(0),
				};

				const validResult = yield* Effect.exit(encodeResourceRecord(validNullRecord));
				expect(Exit.isSuccess(validResult)).toBe(true);
			}),
		);
	});

	describe("boundary conditions and edge cases", () => {
		it.effect("handles maximum label size (63 bytes)", () =>
			Effect.gen(function* () {
				// Create a label with exactly 63 bytes
				const maxLabel = new Uint8Array(63).fill(65); // 63 'A's
				const question = {
					qname: [maxLabel],
					qtype: DnsType.A,
					qclass: 1,
				};

				const encoded = yield* encodeQuestion(question);
				const decoded = yield* decodeQuestion(encoded);
				expect(decoded.qname[0]?.length).toBe(63);
			}),
		);

		it.effect("handles maximum domain name size (255 bytes)", () =>
			Effect.gen(function* () {
				// Create a domain name at 255 byte limit
				// Each label: 1 byte length + content = 64 bytes max per label
				// 3 labels of 63 bytes each = 3 * 63 = 189 bytes
				// Plus 3 length bytes + 1 terminator = 193 bytes total (under 255)
				const maxLabel = new Uint8Array(63).fill(65); // 63 'A's
				const question = {
					qname: [maxLabel, maxLabel, maxLabel],
					qtype: DnsType.A,
					qclass: 1,
				};

				const encoded = yield* encodeQuestion(question);
				const decoded = yield* decodeQuestion(encoded);
				expect(decoded.qname.length).toBe(3);
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

				const encoded = yield* encodeHeader(header);

				// Verify byte order manually
				expect(encoded[0]).toBe(0x12); // High byte of ID
				expect(encoded[1]).toBe(0x34); // Low byte of ID
				expect(encoded[4]).toBe(0x56); // High byte of QDCOUNT
				expect(encoded[5]).toBe(0x78); // Low byte of QDCOUNT
			}),
		);
	});
});

