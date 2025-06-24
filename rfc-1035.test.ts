import { describe, expect, it } from "@effect/vitest";
import { Effect, Exit, FastCheck as fc, Schema } from "effect";
import {
	decodeHeader,
	encodeHeader,
	decodeQuestion,
	encodeQuestion,
	decodeResourceRecord,
	encodeResourceRecord,
	decodeNameFromUint8Array,
	encodeNameFromUint8Array,
	DnsTypeNameToDnsType,
	Label,
	Name,
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

const arbitraryValidQuestionDnsHeader = fc.record({
	id: fc.integer({ min: 0, max: 65535 }),
	qr: fc.constantFrom(0),
	opcode: fc.constantFrom(0, 1, 2), // QUERY, IQUERY, STATUS only
	aa: fc.constantFrom(0),
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

const arbitraryValidAnswerDnsHeader = fc.record({
	id: fc.integer({ min: 0, max: 65535 }),
	qr: fc.constantFrom(1),
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

// Generate valid DNS header with realistic values
const arbitraryValidDnsHeader = fc.oneof(
	arbitraryValidQuestionDnsHeader,
	arbitraryValidAnswerDnsHeader,
);

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
	qtype: fc.constantFrom(...Object.values(DnsTypeNameToDnsType)),
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
		type: fc.constantFrom(...Object.values(DnsTypeNameToDnsType)),
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

// Generate valid Label instances (Uint8Array with valid characters)
// RFC-1035: Labels can contain letters, digits, and hyphens
// Must start and end with letter or digit, no consecutive hyphens
const arbitraryValidLabel = fc.oneof(
	// Single character (letter or digit)
	fc
		.oneof(
			fc.integer({ min: 65, max: 90 }), // A-Z
			fc.integer({ min: 97, max: 122 }), // a-z
			fc.integer({ min: 48, max: 57 }), // 0-9
		)
		.map((code) => new Uint8Array([code])),

	// Multi-character labels
	fc
		.array(
			fc.oneof(
				fc.integer({ min: 65, max: 90 }), // A-Z
				fc.integer({ min: 97, max: 122 }), // a-z
				fc.integer({ min: 48, max: 57 }), // 0-9
				fc.constant(45), // hyphen
			),
			{ minLength: 2, maxLength: 63 },
		)
		.filter((codes) => {
			// Must start and end with letter or digit (not hyphen)
			const first = codes[0];
			const last = codes[codes.length - 1];
			return first !== 45 && last !== 45;
		})
		.filter((codes) => {
			// No consecutive hyphens
			for (let i = 0; i < codes.length - 1; i++) {
				if (codes[i] === 45 && codes[i + 1] === 45) {
					return false;
				}
			}
			return true;
		})
		.map((codes) => new Uint8Array(codes)),
);

// Generate invalid Label instances for negative testing
const encoder = new TextEncoder();
const encode = (s: string): Uint8Array => encoder.encode(s);

const ALPHA_NUM =
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const ALPHA_NUM_HYPHEN = `${ALPHA_NUM}-`;
const INVALID_CHARS = "~!@#$%^&*()_+`={}[]|:;\"'<>,.?/\\";

const charFrom = (chars: string) => fc.constantFrom(...chars.split(""));

const arbitraryInvalidLabel = fc.oneof(
	// Too long (> 63 bytes)
	fc
		.string({ unit: charFrom(ALPHA_NUM_HYPHEN), minLength: 64, maxLength: 100 })
		.map(encode),

	// Empty label
	fc.constant(encode("")),

	// Starts with hyphen
	fc
		.tuple(
			fc.constant("-"),
			fc.string({
				unit: charFrom(ALPHA_NUM_HYPHEN),
				minLength: 0,
				maxLength: 62,
			}),
		)
		.map(([hyphen, rest]) => encode(`${hyphen}${rest}`)),

	// Ends with hyphen
	fc
		.tuple(
			fc.string({
				unit: charFrom(ALPHA_NUM_HYPHEN),
				minLength: 1,
				maxLength: 62,
			}),
			fc.constant("-"),
		)
		.map(([body, hyphen]) => encode(`${body}${hyphen}`)),

	// Contains invalid characters
	fc
		.tuple(
			fc.string({ unit: charFrom(ALPHA_NUM_HYPHEN), maxLength: 30 }),
			fc.string({ unit: charFrom(INVALID_CHARS), minLength: 1, maxLength: 3 }),
			fc.string({ unit: charFrom(ALPHA_NUM_HYPHEN), maxLength: 30 }),
		)
		.map(([pre, bad, post]) => encode(`${pre}${bad}${post}`.slice(0, 63))),

	// Consecutive hyphens
	fc
		.tuple(
			fc.string({ unit: charFrom(ALPHA_NUM), maxLength: 30 }),
			fc.string({ unit: charFrom(ALPHA_NUM), maxLength: 30 }),
		)
		.map(([left, right]) => encode(`${left}--${right}`)),
);

// Generate valid Name instances (arrays of valid Labels)
// RFC 1035: Names must be 255 octets or less total
const arbitraryValidName = fc
	.array(arbitraryValidLabel, { minLength: 1, maxLength: 127 })
	.filter((labels) => {
		// Calculate total byte length including length prefixes
		const totalLength =
			labels.reduce((sum, label) => sum + label.length + 1, 0) + 1; // +1 for terminator
		return totalLength <= 255;
	});

// 63-byte valid label used to force total name length > 255 bytes
const LABEL_63 = encode("A".repeat(63));

// Generate invalid Name instances for negative testing
const arbitraryInvalidName = fc.oneof(
	// Empty array (no labels)
	fc.constant([]),

	// Name whose encoded length exceeds 255 bytes
	fc.array(fc.constant(LABEL_63), { minLength: 5, maxLength: 10 }),

	// Name containing at least one invalid label while staying ≤ 255 bytes
	fc
		.tuple(
			fc.array(arbitraryValidLabel, { minLength: 0, maxLength: 3 }),
			arbitraryInvalidLabel,
			fc.array(arbitraryValidLabel, { minLength: 0, maxLength: 3 }),
		)
		.map(([pre, invalid, post]) => [...pre, invalid, ...post])
		.filter((labels) => {
			let total = 1; // account for final root byte
			for (const l of labels) total += l.length + 1; // label + separator
			return total <= 255;
		}),

	// Name with an excessive number of labels (edge-case)
	fc.array(fc.constant(encode("A")), { minLength: 256, maxLength: 300 }),
);

// Generate valid Name instances as Uint8Array in wire format
// RFC 1035: Names in wire format have length prefixes and null terminator
const arbitraryValidNameUint8Array = arbitraryValidName.map((name) => {
	// Calculate total wire format size: length bytes + label bytes + terminator
	const totalLength =
		name.reduce((sum, label) => sum + label.length + 1, 0) + 1;
	const buffer = new Uint8Array(totalLength);

	let offset = 0;
	for (const label of name) {
		buffer[offset++] = label.length; // Length prefix
		buffer.set(label, offset);
		offset += label.length;
	}
	buffer[offset] = 0; // Null terminator

	return buffer;
});

// Generate invalid Name instances as Uint8Array for negative testing
const arbitraryInvalidNameUint8Array = fc.oneof(
	// Empty buffer
	fc.constant(new Uint8Array(0)),

	// Buffer with only length byte but no data
	fc.constant(new Uint8Array([5])),

	// Buffer missing null terminator
	fc.constant(new Uint8Array([4, 116, 101, 115, 116])), // "test" without terminator

	// Buffer with invalid length (points beyond buffer)
	fc.constant(new Uint8Array([10, 116, 101, 115, 116, 0])), // length=10 but only 4 bytes follow

	// Buffer exceeding 255 bytes (wire format)
	fc.constant(new Uint8Array(300).fill(65)), // 300 'A's without proper structure

	// Buffer with oversized label (>63 bytes)
	fc
		.tuple(
			fc.constant(64), // Invalid length > 63
			fc.uint8Array({ minLength: 64, maxLength: 64 }),
			fc.constant(0),
		)
		.map(
			([length, data, terminator]) =>
				new Uint8Array([length, ...data, terminator]),
		),
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

		it.effect(
			"validates semantic consistency between QR and other fields",
			() =>
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

	describe("Label", () => {
		it.effect.prop(
			"successfully validates valid RFC-compliant labels",
			[arbitraryValidLabel],
			([uint8Array]) =>
				Effect.gen(function* () {
					const result = yield* Effect.exit(
						Effect.sync(() => Schema.is(Label)(uint8Array)),
					);
					expect(result).toEqual(Exit.succeed(true));
				}),
		);

		it.effect.prop(
			"rejects invalid labels",
			[arbitraryInvalidLabel],
			([uint8Array]) =>
				Effect.gen(function* () {
					const result = yield* Effect.exit(
						Effect.sync(() => Schema.is(Label)(uint8Array)),
					);
					expect(result).toEqual(Exit.succeed(false));
				}),
		);

		it.effect("validates label length boundary (63 bytes)", () =>
			Effect.gen(function* () {
				// Exactly 63 bytes - should pass
				const maxLabel = new Uint8Array(63).fill(65); // 63 'A's
				const validResult = yield* Effect.exit(
					Effect.sync(() => Schema.is(Label)(maxLabel)),
				);
				expect(validResult).toEqual(Exit.succeed(true));

				// 64 bytes - should fail
				const tooLongLabel = new Uint8Array(64).fill(65); // 64 'A's
				const invalidResult = yield* Effect.exit(
					Effect.sync(() => Schema.is(Label)(tooLongLabel)),
				);
				expect(invalidResult).toEqual(Exit.succeed(false));
			}),
		);

		it.effect("validates character restrictions", () =>
			Effect.gen(function* () {
				// Valid characters: letters (A-Z, a-z), digits (0-9), hyphens (-)
				const validChars = [
					new Uint8Array([65]), // 'A'
					new Uint8Array([90]), // 'Z'
					new Uint8Array([97]), // 'a'
					new Uint8Array([122]), // 'z'
					new Uint8Array([48]), // '0'
					new Uint8Array([57]), // '9'
					new Uint8Array([65, 45, 65]), // 'A-A' (hyphen in middle)
					new Uint8Array([48, 45, 57]), // '0-9' (digit-hyphen-digit)
				];

				for (const label of validChars) {
					const result = yield* Effect.exit(
						Effect.sync(() => Schema.is(Label)(label)),
					);
					expect(result).toEqual(Exit.succeed(true));
				}

				// Invalid characters: everything else
				const invalidChars = [
					new Uint8Array([32]), // space
					new Uint8Array([64]), // '@'
					new Uint8Array([95]), // '_'
					new Uint8Array([46]), // '.'
					new Uint8Array([33]), // '!'
					new Uint8Array([126]), // '~'
					new Uint8Array([47]), // '/'
					new Uint8Array([58]), // ':'
				];

				for (const label of invalidChars) {
					const result = yield* Effect.exit(
						Effect.sync(() => Schema.is(Label)(label)),
					);
					expect(result).toEqual(Exit.succeed(false));
				}
			}),
		);

		it.effect("validates hyphen placement rules", () =>
			Effect.gen(function* () {
				// Cannot start with hyphen
				const startsWithHyphen = new Uint8Array([45, 65]); // '-A'
				const startResult = yield* Effect.exit(
					Effect.sync(() => Schema.is(Label)(startsWithHyphen)),
				);
				expect(startResult).toEqual(Exit.succeed(false));

				// Cannot end with hyphen
				const endsWithHyphen = new Uint8Array([65, 45]); // 'A-'
				const endResult = yield* Effect.exit(
					Effect.sync(() => Schema.is(Label)(endsWithHyphen)),
				);
				expect(endResult).toEqual(Exit.succeed(false));

				// Can have hyphen in middle
				const validHyphen = new Uint8Array([65, 45, 65]); // 'A-A'
				const validResult = yield* Effect.exit(
					Effect.sync(() => Schema.is(Label)(validHyphen)),
				);
				expect(validResult).toEqual(Exit.succeed(true));

				// Cannot have consecutive hyphens
				const consecutiveHyphens = new Uint8Array([65, 45, 45, 65]); // 'A--A'
				const consecutiveResult = yield* Effect.exit(
					Effect.sync(() => Schema.is(Label)(consecutiveHyphens)),
				);
				expect(consecutiveResult).toEqual(Exit.succeed(false));
			}),
		);

		it.effect("validates edge cases", () =>
			Effect.gen(function* () {
				// Empty label - should fail (RFC requires 1-63 octets)
				const empty = new Uint8Array(0);
				const emptyResult = yield* Effect.exit(
					Effect.sync(() => Schema.is(Label)(empty)),
				);
				expect(emptyResult).toEqual(Exit.succeed(false));

				// Single character letter - should pass
				const singleLetter = new Uint8Array([65]); // 'A'
				const singleLetterResult = yield* Effect.exit(
					Effect.sync(() => Schema.is(Label)(singleLetter)),
				);
				expect(singleLetterResult).toEqual(Exit.succeed(true));

				// Single character digit - should pass
				const singleDigit = new Uint8Array([48]); // '0'
				const singleDigitResult = yield* Effect.exit(
					Effect.sync(() => Schema.is(Label)(singleDigit)),
				);
				expect(singleDigitResult).toEqual(Exit.succeed(true));

				// Single hyphen - should fail (cannot start with hyphen)
				const singleHyphen = new Uint8Array([45]); // '-'
				const singleHyphenResult = yield* Effect.exit(
					Effect.sync(() => Schema.is(Label)(singleHyphen)),
				);
				expect(singleHyphenResult).toEqual(Exit.succeed(false));

				// Two valid characters - should pass
				const two = new Uint8Array([65, 66]); // 'AB'
				const twoResult = yield* Effect.exit(
					Effect.sync(() => Schema.is(Label)(two)),
				);
				expect(twoResult).toEqual(Exit.succeed(true));

				// Mixed letters, digits, and valid hyphen - should pass
				const mixed = new Uint8Array([65, 48, 45, 66, 57]); // 'A0-B9'
				const mixedResult = yield* Effect.exit(
					Effect.sync(() => Schema.is(Label)(mixed)),
				);
				expect(mixedResult).toEqual(Exit.succeed(true));
			}),
		);

		it.effect.prop(
			"roundtrip validation preserves valid labels",
			[arbitraryValidLabel],
			([label]) =>
				Effect.gen(function* () {
					// Test that valid labels pass validation consistently
					const result1 = yield* Effect.exit(
						Effect.sync(() => Schema.is(Label)(label)),
					);
					expect(result1).toEqual(Exit.succeed(true));

					// Test that Schema.decodeUnknown and Schema.encodeUnknown work
					const decoded = yield* Schema.decodeUnknown(Label)(label);
					const encoded = yield* Schema.encodeUnknown(Label)(decoded);

					// Should be identical since Label is just Uint8Array with validation
					expect(Array.from(encoded)).toEqual(Array.from(label));
				}),
		);

		it.effect.prop(
			"roundtrip encoding fails for invalid labels",
			[arbitraryInvalidLabel],
			([label]) =>
				Effect.gen(function* () {
					// Invalid labels should fail decoding
					const result = yield* Effect.exit(Schema.decodeUnknown(Label)(label));
					expect(Exit.isFailure(result)).toBe(true);
				}),
		);

		it.effect("validates roundtrip edge cases for labels", () =>
			Effect.gen(function* () {
				// Test boundary cases
				const testCases = [
					new Uint8Array([65]), // Single 'A'
					new Uint8Array([48]), // Single '0'
					new Uint8Array(63).fill(65), // Max length (63 'A's)
					new Uint8Array([65, 45, 90]), // 'A-Z'
					new Uint8Array([48, 45, 57]), // '0-9'
				];

				for (const label of testCases) {
					const decoded = yield* Schema.decodeUnknown(Label)(label);
					const encoded = yield* Schema.encodeUnknown(Label)(decoded);
					expect(Array.from(encoded)).toEqual(Array.from(label));
				}
			}),
		);
	});

	describe("Name", () => {
		it.effect.prop(
			"successfully validates valid RFC-compliant names",
			[arbitraryValidName],
			([labels]) =>
				Effect.gen(function* () {
					const result = yield* Effect.exit(
						Effect.sync(() => Schema.is(Name)(labels)),
					);
					expect(result).toEqual(Exit.succeed(true));
				}),
		);

		it.effect.prop(
			"rejects invalid names",
			[arbitraryInvalidName],
			([labels]) =>
				Effect.gen(function* () {
					const result = yield* Effect.exit(
						Effect.sync(() => Schema.is(Name)(labels)),
					);
					expect(result).toEqual(Exit.succeed(false));
				}),
		);

		it.effect("validates name length boundary (255 octets)", () =>
			Effect.gen(function* () {
				// Create a name at exactly 255 octets total
				// Each label: 1 byte length + content
				// 4 labels of 63 bytes each = 4 * 63 = 252 bytes
				// Plus 4 length bytes + 1 terminator = 257 bytes (exceeds limit)
				// So use 3 labels of 63 bytes = 3 * 63 = 189 bytes
				// Plus 3 length bytes + 1 terminator = 193 bytes (within limit)
				const maxLabel = new Uint8Array(63).fill(65); // 63 'A's
				const validName = [maxLabel, maxLabel, maxLabel]; // 193 total bytes

				const validResult = yield* Effect.exit(
					Effect.sync(() => Schema.is(Name)(validName)),
				);
				expect(validResult).toEqual(Exit.succeed(true));

				// Create a name exceeding 255 octets
				const oversizedName = [
					maxLabel,
					maxLabel,
					maxLabel,
					maxLabel,
					maxLabel,
				];
				const invalidResult = yield* Effect.exit(
					Effect.sync(() => Schema.is(Name)(oversizedName)),
				);
				expect(invalidResult).toEqual(Exit.succeed(false));
			}),
		);

		it.effect("validates empty name arrays", () =>
			Effect.gen(function* () {
				// Empty array should fail (RFC requires at least one label)
				const emptyName: Uint8Array[] = [];
				const result = yield* Effect.exit(
					Effect.sync(() => Schema.is(Name)(emptyName)),
				);
				expect(result).toEqual(Exit.succeed(false));
			}),
		);

		it.effect("validates individual label compliance within names", () =>
			Effect.gen(function* () {
				// Name with valid labels should pass
				const validLabels = [
					new Uint8Array([65, 66, 67]), // "ABC"
					new Uint8Array([49, 50, 51]), // "123"
					new Uint8Array([88, 45, 89]), // "X-Y"
				];
				const validResult = yield* Effect.exit(
					Effect.sync(() => Schema.is(Name)(validLabels)),
				);
				expect(validResult).toEqual(Exit.succeed(true));

				// Name with invalid label should fail
				const invalidLabels = [
					new Uint8Array([65, 66, 67]), // "ABC" (valid)
					new Uint8Array([45, 66, 67]), // "-BC" (invalid - starts with hyphen)
					new Uint8Array([88, 89, 90]), // "XYZ" (valid)
				];
				const invalidResult = yield* Effect.exit(
					Effect.sync(() => Schema.is(Name)(invalidLabels)),
				);
				expect(invalidResult).toEqual(Exit.succeed(false));
			}),
		);

		it.effect("validates maximum label count", () =>
			Effect.gen(function* () {
				// Name with reasonable number of labels should pass
				const reasonableLabels = Array(10).fill(new Uint8Array([65])); // 10 single 'A' labels
				const reasonableResult = yield* Effect.exit(
					Effect.sync(() => Schema.is(Name)(reasonableLabels)),
				);
				expect(reasonableResult).toEqual(Exit.succeed(true));

				// Name with excessive number of labels should fail due to size limit
				const excessiveLabels = Array(300).fill(new Uint8Array([65])); // 300 single 'A' labels
				const excessiveResult = yield* Effect.exit(
					Effect.sync(() => Schema.is(Name)(excessiveLabels)),
				);
				expect(excessiveResult).toEqual(Exit.succeed(false));
			}),
		);

		it.effect("validates realistic domain name structures", () =>
			Effect.gen(function* () {
				// Single label domain (rare but valid)
				const singleLabel = [new Uint8Array([116, 101, 115, 116])]; // "test"
				const singleResult = yield* Effect.exit(
					Effect.sync(() => Schema.is(Name)(singleLabel)),
				);
				expect(singleResult).toEqual(Exit.succeed(true));

				// Standard domain.tld
				const standardDomain = [
					new Uint8Array([101, 120, 97, 109, 112, 108, 101]), // "example"
					new Uint8Array([99, 111, 109]), // "com"
				];
				const standardResult = yield* Effect.exit(
					Effect.sync(() => Schema.is(Name)(standardDomain)),
				);
				expect(standardResult).toEqual(Exit.succeed(true));

				// Subdomain.domain.tld
				const subdomain = [
					new Uint8Array([119, 119, 119]), // "www"
					new Uint8Array([101, 120, 97, 109, 112, 108, 101]), // "example"
					new Uint8Array([99, 111, 109]), // "com"
				];
				const subdomainResult = yield* Effect.exit(
					Effect.sync(() => Schema.is(Name)(subdomain)),
				);
				expect(subdomainResult).toEqual(Exit.succeed(true));
			}),
		);

		it.effect("validates edge cases and boundary conditions", () =>
			Effect.gen(function* () {
				// Single character labels
				const singleChar = [
					new Uint8Array([65]), // "A"
					new Uint8Array([49]), // "1"
				];
				const singleCharResult = yield* Effect.exit(
					Effect.sync(() => Schema.is(Name)(singleChar)),
				);
				expect(singleCharResult).toEqual(Exit.succeed(true));

				// Maximum length single label
				const maxSingleLabel = [new Uint8Array(63).fill(65)]; // 63 'A's
				const maxSingleResult = yield* Effect.exit(
					Effect.sync(() => Schema.is(Name)(maxSingleLabel)),
				);
				expect(maxSingleResult).toEqual(Exit.succeed(true));

				// Mixed case and digits
				const mixedCase = [
					new Uint8Array([65, 97, 49, 66, 98, 50]), // "Aa1Bb2"
					new Uint8Array([67, 99, 51, 68, 100, 52]), // "Cc3Dd4"
				];
				const mixedCaseResult = yield* Effect.exit(
					Effect.sync(() => Schema.is(Name)(mixedCase)),
				);
				expect(mixedCaseResult).toEqual(Exit.succeed(true));

				// Labels with valid hyphens
				const hyphenLabels = [
					new Uint8Array([97, 45, 98]), // "a-b"
					new Uint8Array([49, 45, 50, 45, 51]), // "1-2-3"
					new Uint8Array([120, 45, 121, 45, 122]), // "x-y-z"
				];
				const hyphenResult = yield* Effect.exit(
					Effect.sync(() => Schema.is(Name)(hyphenLabels)),
				);
				expect(hyphenResult).toEqual(Exit.succeed(true));
			}),
		);

		it.effect.prop(
			"roundtrip validation preserves valid names",
			[arbitraryValidName],
			([name]) =>
				Effect.gen(function* () {
					// Test that valid names pass validation consistently
					const result1 = yield* Effect.exit(
						Effect.sync(() => Schema.is(Name)(name)),
					);
					expect(result1).toEqual(Exit.succeed(true));

					// Test that Schema.decodeUnknown and Schema.encodeUnknown work
					const decoded = yield* Schema.decodeUnknown(Name)(name);
					const encoded = yield* Schema.encodeUnknown(Name)(decoded);

					// Should be identical since Name is just Array<Label> with validation
					expect(encoded.length).toEqual(name.length);
					for (let i = 0; i < name.length; i++) {
						expect(encoded[i]).toEqual(name[i]);
					}
				}),
		);

		it.effect.prop(
			"roundtrip encoding fails for invalid names",
			[arbitraryInvalidName],
			([name]) =>
				Effect.gen(function* () {
					// Invalid names should fail decoding
					const result = yield* Effect.exit(Schema.decodeUnknown(Name)(name));
					expect(Exit.isFailure(result)).toBe(true);
				}),
		);

		it.effect("validates roundtrip edge cases for names", () =>
			Effect.gen(function* () {
				// Test boundary cases
				const testCases = [
					// Single label
					[new Uint8Array([65])], // ["A"]
					// Two labels
					[new Uint8Array([65, 66]), new Uint8Array([67, 68])], // ["AB", "CD"]
					// Maximum single label
					[new Uint8Array(63).fill(65)], // [63 'A's]
					// Multiple labels within size limit
					[
						new Uint8Array([116, 101, 115, 116]), // "test"
						new Uint8Array([101, 120, 97, 109, 112, 108, 101]), // "example"
						new Uint8Array([99, 111, 109]), // "com"
					],
					// Labels with hyphens
					[
						new Uint8Array([97, 45, 98]), // "a-b"
						new Uint8Array([49, 45, 50]), // "1-2"
					],
				];

				for (const name of testCases) {
					const decoded = yield* Schema.decodeUnknown(Name)(name);
					const encoded = yield* Schema.encodeUnknown(Name)(decoded);

					expect(encoded.length).toBe(name.length);
					for (let i = 0; i < name.length; i++) {
						expect(encoded[i]).toEqual(name[i]);
					}
				}
			}),
		);

		it.effect("validates roundtrip consistency with schema validation", () =>
			Effect.gen(function* () {
				// Test that roundtrip encoding preserves validation results
				const validName = [
					new Uint8Array([119, 119, 119]), // "www"
					new Uint8Array([101, 120, 97, 109, 112, 108, 101]), // "example"
					new Uint8Array([99, 111, 109]), // "com"
				];

				// Should validate successfully
				const preValidation = yield* Effect.exit(
					Effect.sync(() => Schema.is(Name)(validName)),
				);
				expect(preValidation).toEqual(Exit.succeed(true));

				// Roundtrip through schema
				const decoded = yield* Schema.decodeUnknown(Name)(validName);
				const encoded = yield* Schema.encodeUnknown(Name)(decoded);

				// Should still validate successfully
				const postValidation = yield* Effect.exit(
					Effect.sync(() => Schema.is(Name)(encoded)),
				);
				expect(postValidation).toEqual(Exit.succeed(true));

				// Content should be identical
				expect(encoded.length).toBe(validName.length);
				for (let i = 0; i < validName.length; i++) {
					expect(encoded[i]).toEqual(validName[i]);
				}
			}),
		);

		describe("binary encoding/decoding", () => {
			it.effect.prop(
				"decodeNameFromUint8Array successfully decodes valid wire format names",
				[arbitraryValidNameUint8Array],
				([uint8Array]) =>
					Effect.gen(function* () {
						const result = yield* Effect.exit(
							decodeNameFromUint8Array(uint8Array),
						);
						if (Exit.isFailure(result)) {
							console.log(JSON.stringify(result, null, 2));
						}

						expect(Exit.isSuccess(result)).toBe(true);

						if (Exit.isSuccess(result)) {
							const name = result.value;
							// Verify structure is valid
							expect(Array.isArray(name)).toBe(true);
							expect(name.length).toBeGreaterThan(0);

							// Verify each label is valid
							for (const label of name) {
								expect(label.length).toBeLessThanOrEqual(63);
								expect(label.length).toBeGreaterThan(0);
							}
						}
					}),
			);

			it.effect.prop(
				"decodeNameFromUint8Array rejects invalid wire format names",
				[arbitraryInvalidNameUint8Array],
				([uint8Array]) =>
					Effect.gen(function* () {
						const result = yield* Effect.exit(
							decodeNameFromUint8Array(uint8Array),
						);
						expect(Exit.isFailure(result)).toBe(true);
					}),
			);

			it.effect.prop(
				"encodeNameFromUint8Array successfully encodes valid names",
				[arbitraryValidName],
				([name]) =>
					Effect.gen(function* () {
						const result = yield* Effect.exit(encodeNameFromUint8Array(name));
						expect(Exit.isSuccess(result)).toBe(true);

						if (Exit.isSuccess(result)) {
							const encoded = result.value;
							// Verify wire format structure
							expect(encoded.length).toBeGreaterThan(0);
							expect(encoded[encoded.length - 1]).toBe(0); // Ends with null terminator

							// Verify length prefixes are reasonable
							let offset = 0;
							for (const label of name) {
								expect(encoded[offset]).toBe(label.length); // Length prefix matches
								offset += label.length + 1;
							}
						}
					}),
			);

			it.effect.prop(
				"encodeNameFromUint8Array rejects invalid names",
				[arbitraryInvalidName],
				([name]) =>
					Effect.gen(function* () {
						const result = yield* Effect.exit(encodeNameFromUint8Array(name));
						expect(Exit.isFailure(result)).toBe(true);
					}),
			);

			it.effect.prop(
				"roundtrip binary encoding preserves valid names",
				[arbitraryValidNameUint8Array],
				([uint8Array]) =>
					Effect.gen(function* () {
						const decoded = yield* decodeNameFromUint8Array(uint8Array);
						const encoded = yield* encodeNameFromUint8Array(decoded);

						// Should be identical byte arrays
						expect(encoded).toEqual(uint8Array);
					}),
			);

			it.effect("validates specific wire format cases", () =>
				Effect.gen(function* () {
					// Single label "test"
					//                                 [4, t,   e,   s,   t,   0]
					const singleLabel = new Uint8Array([4, 116, 101, 115, 116, 0]);
					const decoded1 = yield* decodeNameFromUint8Array(singleLabel);
					expect(decoded1.length).toBe(1);
					expect(Array.from(decoded1[0] ?? [])).toEqual([116, 101, 115, 116]);

					// Two labels "www.example"
					const twoLabels = new Uint8Array([
						3, 119, 119, 119, 7, 101, 120, 97, 109, 112, 108, 101, 0,
					]);
					const decoded2 = yield* decodeNameFromUint8Array(twoLabels);
					expect(decoded2.length).toBe(2);
					expect(Array.from(decoded2[0] ?? [])).toEqual([119, 119, 119]); // "www"
					expect(Array.from(decoded2[1] ?? [])).toEqual([
						101, 120, 97, 109, 112, 108, 101,
					]); // "example"

					// Empty name (just terminator)
					const emptyName = new Uint8Array([0]);
					const result = yield* Effect.exit(
						decodeNameFromUint8Array(emptyName),
					);
					expect(Exit.isFailure(result)).toBe(true); // Should fail - no labels before terminator
				}),
			);

			it.effect("validates edge cases and error conditions", () =>
				Effect.gen(function* () {
					// Buffer too short
					const tooShort = new Uint8Array([5, 116]);
					const result1 = yield* Effect.exit(
						decodeNameFromUint8Array(tooShort),
					);
					expect(Exit.isFailure(result1)).toBe(true);

					// Missing terminator
					const noTerminator = new Uint8Array([4, 116, 101, 115, 116]);
					const result2 = yield* Effect.exit(
						decodeNameFromUint8Array(noTerminator),
					);
					expect(Exit.isFailure(result2)).toBe(true);

					// Label too long (>63 bytes)
					const longLabel = new Uint8Array([64, ...new Array(64).fill(65), 0]);
					const result3 = yield* Effect.exit(
						decodeNameFromUint8Array(longLabel),
					);
					expect(Exit.isFailure(result3)).toBe(true);

					// Total size exceeding 255 bytes
					const oversized = new Uint8Array(300);
					oversized[0] = 255; // Impossible length
					const result4 = yield* Effect.exit(
						decodeNameFromUint8Array(oversized),
					);
					expect(Exit.isFailure(result4)).toBe(true);
				}),
			);

			it.effect("validates wire format encoding consistency", () =>
				Effect.gen(function* () {
					// Test specific known encodings
					const testCases = [
						{
							name: [new Uint8Array([65])], // ["A"]
							expected: new Uint8Array([1, 65, 0]),
						},
						{
							name: [
								new Uint8Array([116, 101, 115, 116]), // "test"
								new Uint8Array([99, 111, 109]), // "com"
							],
							expected: new Uint8Array([
								4, 116, 101, 115, 116, 3, 99, 111, 109, 0,
							]),
						},
						{
							name: [
								new Uint8Array([65, 45, 66]), // "A-B"
								new Uint8Array([49, 50, 51]), // "123"
							],
							expected: new Uint8Array([3, 65, 45, 66, 3, 49, 50, 51, 0]),
						},
					];

					for (const testCase of testCases) {
						const encoded = yield* encodeNameFromUint8Array(testCase.name);
						expect(Array.from(encoded)).toEqual(Array.from(testCase.expected));

						// Verify roundtrip
						const decoded = yield* decodeNameFromUint8Array(encoded);
						expect(decoded.length).toBe(testCase.name.length);
						for (let i = 0; i < testCase.name.length; i++) {
							expect(decoded[i]).toEqual(testCase.name[i]);
						}
					}
				}),
			);

			it.effect("validates RFC 1035 size limits in wire format", () =>
				Effect.gen(function* () {
					// Maximum valid label (63 bytes)
					const maxLabel = new Uint8Array(63).fill(65); // 63 'A's
					const maxLabelName = [maxLabel];
					const encoded1 = yield* encodeNameFromUint8Array(maxLabelName);
					const decoded1 = yield* decodeNameFromUint8Array(encoded1);
					expect(decoded1[0]?.length).toBe(63);

					// Multiple labels approaching size limit
					const multipleLabels = [
						new Uint8Array(60).fill(65), // 60 'A's
						new Uint8Array(60).fill(66), // 60 'B's
						new Uint8Array(60).fill(67), // 60 'C's
						new Uint8Array(60).fill(68), // 60 'D's
					];

					// This should be within limits: 4 * (60 + 1) + 1 = 245 bytes
					const encoded2 = yield* encodeNameFromUint8Array(multipleLabels);
					const decoded2 = yield* decodeNameFromUint8Array(encoded2);
					expect(decoded2.length).toBe(4);
				}),
			);
		});
	});

	describe.only("question", () => {
		it.effect.prop(
			"successfully decodes valid RFC-compliant questions",
			[arbitraryValidDnsQuestionUint8Array],
			([uint8Array]) =>
				Effect.gen(function* () {
					const result = yield* Effect.exit(decodeQuestion(uint8Array));
					if (Exit.isFailure(result)) {
						console.log(JSON.stringify(result));
					}
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
						qtype: DnsTypeNameToDnsType.A,
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
					{ qtype: DnsTypeNameToDnsType.A, qclass: 0 }, // Invalid QCLASS 0
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
		//
		// it.effect.prop(
		// 	"roundtrip encoding preserves valid questions",
		// 	[arbitraryValidDnsQuestionUint8Array],
		// 	([uint8Array]) =>
		// 		Effect.gen(function* () {
		// 			const decoded = yield* decodeQuestion(uint8Array);
		// 			const encoded = yield* encodeQuestion(decoded);
		// 			expect(Array.from(encoded)).toEqual(Array.from(uint8Array));
		// 		}),
		// );
		//
		// it.effect("handles internationalized domain names", () =>
		// 	Effect.gen(function* () {
		// 		// IDN should be punycode encoded, not raw UTF-8
		// 		const unicodeDomain = "xn--fsq.com"; // punycode for "中.com"
		// 		const question = {
		// 			qname: [
		// 				new Uint8Array(Array.from("xn--fsq", (c) => c.charCodeAt(0))),
		// 				new Uint8Array(Array.from("com", (c) => c.charCodeAt(0))),
		// 			],
		// 			qtype: DnsType.A,
		// 			qclass: 1,
		// 		};
		//
		// 		const encoded = yield* encodeQuestion(question);
		// 		const decoded = yield* decodeQuestion(encoded);
		// 		expect(decoded.qname.length).toBe(2);
		// 	}),
		// );
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
					type: DnsTypeNameToDnsType.A,
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
					type: DnsTypeNameToDnsType.A,
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
					type: DnsTypeNameToDnsType.MX,
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

				const validResult = yield* Effect.exit(
					decodeResourceRecord(validTtlBytes),
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
					type: DnsTypeNameToDnsType.A,
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
					type: DnsTypeNameToDnsType.NULL,
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
	});

	describe("boundary conditions and edge cases", () => {
		it.effect("handles maximum label size (63 bytes)", () =>
			Effect.gen(function* () {
				// Create a label with exactly 63 bytes
				const maxLabel = new Uint8Array(63).fill(65); // 63 'A's
				const question = {
					qname: [maxLabel],
					qtype: DnsTypeNameToDnsType.A,
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
					qtype: DnsTypeNameToDnsType.A,
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

		it.effect("validates Name usage in Question context", () =>
			Effect.gen(function* () {
				// Valid Name should work in Question
				const validName = [
					new Uint8Array([119, 119, 119]), // "www"
					new Uint8Array([101, 120, 97, 109, 112, 108, 101]), // "example"
					new Uint8Array([99, 111, 109]), // "com"
				];

				const question = {
					qname: validName,
					qtype: DnsTypeNameToDnsType.A,
					qclass: 1,
				};

				const encoded = yield* encodeQuestion(question);
				const decoded = yield* decodeQuestion(encoded);
				expect(decoded.qname.length).toBe(3);

				// Invalid Name should fail in Question
				const invalidName = [
					new Uint8Array([45, 119, 119, 119]), // "-www" (starts with hyphen)
					new Uint8Array([101, 120, 97, 109, 112, 108, 101]), // "example"
					new Uint8Array([99, 111, 109]), // "com"
				];

				const invalidQuestion = {
					qname: invalidName,
					qtype: DnsTypeNameToDnsType.A,
					qclass: 1,
				};

				const result = yield* Effect.exit(encodeQuestion(invalidQuestion));
				expect(Exit.isFailure(result)).toBe(true);
			}),
		);

		it.effect("validates Name usage in ResourceRecord context", () =>
			Effect.gen(function* () {
				// Valid Name should work in ResourceRecord
				const validName = [
					new Uint8Array([109, 97, 105, 108]), // "mail"
					new Uint8Array([101, 120, 97, 109, 112, 108, 101]), // "example"
					new Uint8Array([99, 111, 109]), // "com"
				];

				const record = {
					name: validName,
					type: DnsTypeNameToDnsType.A,
					class: 1,
					ttl: 3600,
					rdlength: 4,
					rdata: new Uint8Array([192, 0, 2, 1]),
				};

				const encoded = yield* encodeResourceRecord(record);
				const decoded = yield* decodeResourceRecord(encoded);
				expect(decoded.name.length).toBe(3);

				// Invalid Name should fail in ResourceRecord
				const invalidName = [
					new Uint8Array([109, 97, 105, 108, 45]), // "mail-" (ends with hyphen)
					new Uint8Array([101, 120, 97, 109, 112, 108, 101]), // "example"
					new Uint8Array([99, 111, 109]), // "com"
				];

				const invalidRecord = {
					name: invalidName,
					type: DnsTypeNameToDnsType.A,
					class: 1,
					ttl: 3600,
					rdlength: 4,
					rdata: new Uint8Array([192, 0, 2, 1]),
				};

				const result = yield* Effect.exit(encodeResourceRecord(invalidRecord));
				expect(Exit.isFailure(result)).toBe(true);
			}),
		);

		it.effect.prop(
			"validates Name roundtrip consistency across contexts",
			[arbitraryValidName],
			([name]) =>
				Effect.gen(function* () {
					// Test Name in Question context
					const question = {
						qname: name,
						qtype: DnsTypeNameToDnsType.A,
						qclass: 1,
					};

					const questionEncoded = yield* encodeQuestion(question);
					const questionDecoded = yield* decodeQuestion(questionEncoded);
					expect(questionDecoded.qname.length).toEqual(name.length);
					//
					// // Test same Name in ResourceRecord context
					// const record = {
					// 	name: name,
					// 	type: DnsType.A,
					// 	class: 1,
					// 	ttl: 3600,
					// 	rdlength: 4,
					// 	rdata: new Uint8Array([192, 0, 2, 1]),
					// };
					//
					// const recordEncoded = yield* encodeResourceRecord(record);
					// const recordDecoded = yield* decodeResourceRecord(recordEncoded);
					// expect(recordDecoded.name.length).toBe(name.length);
					//
					// // Both contexts should preserve the same Name structure
					// for (let i = 0; i < name.length; i++) {
					// 	expect(Array.from(questionDecoded.qname[i] || [])).toEqual(
					// 		Array.from(recordDecoded.name[i] || []),
					// 	);
					// }
				}),
		);
	});
});
