import { describe, expect, it } from "@effect/vitest";
import { Effect, Exit, FastCheck as fc } from "effect";
import {
	decodeHeader,
	encodeHeader,
	decodeQuestion,
	encodeQuestion,
	decodeResourceRecord,
	DnsType,
} from ".";

const arbitraryDnsHeaderUint8Array = fc.uint8Array({
	maxLength: 12,
	minLength: 12,
});

// Generate a valid DNS label (1-63 bytes, excluding length byte)
const arbitraryDnsLabel = fc
	.uint8Array({ minLength: 1, maxLength: 63 })
	.map((arr) => new Uint8Array(arr));

// Generate a valid DNS name (array of labels)
const arbitraryDnsName = fc
	.array(arbitraryDnsLabel, { minLength: 1, maxLength: 4 })
	.filter((labels) => {
		// Ensure total length doesn't exceed 255 bytes
		const totalLength =
			labels.reduce((sum, label) => sum + label.length + 1, 0) + 1; // +1 for each length byte, +1 for terminator
		return totalLength <= 255;
	});

// Generate a valid DNS TYPE value from RFC 1035
const arbitraryDnsType = fc.constantFrom(...Object.values(DnsType));

// Generate a valid DNS question structure
const arbitraryDnsQuestion = fc.record({
	qname: arbitraryDnsName,
	qtype: arbitraryDnsType,
	qclass: fc.integer({ min: 0, max: 65535 }),
});

// Generate a valid DNS question as Uint8Array
const arbitraryDnsQuestionUint8Array = arbitraryDnsQuestion.map((question) => {
	const totalLength =
		question.qname.reduce((sum, label) => sum + label.length + 1, 0) + 5; // +1 for each length byte, +5 for terminator and qtype/qclass
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
});

describe("rfc-1035", () => {
	describe("header", () => {
		it.effect.prop(
			"successfully decodes a Uint8Array to a Header",
			[arbitraryDnsHeaderUint8Array],
			([uint8Array]) =>
				Effect.gen(function* () {
					const result = yield* Effect.exit(decodeHeader(uint8Array));
					expect(Exit.isSuccess(result)).toBe(true);
				}),
		);

		it.effect.prop(
			"fails to decode if Uint8Array is not 12 bytes",
			[
				fc
					.uint8Array({ minLength: 0, maxLength: 24 })
					.filter((arr) => arr.length !== 12),
			],
			([uint8Array]) =>
				Effect.gen(function* () {
					const result = yield* Effect.exit(decodeHeader(uint8Array));
					expect(Exit.isFailure(result)).toBe(true);
				}),
		);

		it.effect.prop(
			"encodeHeader and decodeHeader are inverses (roundtrip)",
			[arbitraryDnsHeaderUint8Array],
			([uint8Array]) =>
				Effect.gen(function* () {
					const decoded = yield* decodeHeader(uint8Array);

					const encoded = yield* encodeHeader(decoded);
					expect(Array.from(encoded)).toEqual(Array.from(uint8Array));
				}),
		);

		it.effect("decodes all-zero header", () =>
			Effect.gen(function* () {
				const arr = new Uint8Array(12);
				const result = yield* Effect.exit(decodeHeader(arr));
				expect(Exit.isSuccess(result)).toBe(true);
			}),
		);

		it.effect("decodes all-ones header", () =>
			Effect.gen(function* () {
				const arr = new Uint8Array(12).fill(0xff);
				const result = yield* Effect.exit(decodeHeader(arr));
				expect(Exit.isSuccess(result)).toBe(true);
			}),
		);

		it.effect.prop(
			"decoding then encoding yields a Uint8Array of length 12",
			[arbitraryDnsHeaderUint8Array],
			([uint8Array]) =>
				Effect.gen(function* () {
					const header = yield* decodeHeader(uint8Array);
					const encoded = yield* encodeHeader(header);
					expect(encoded.length).toBe(12);
				}),
		);
	});

	describe("question", () => {
		it.effect.prop(
			"successfully decodes a Uint8Array to a Question",
			[arbitraryDnsQuestionUint8Array],
			([uint8Array]) =>
				Effect.gen(function* () {
					const result = yield* Effect.exit(decodeQuestion(uint8Array));
					expect(Exit.isSuccess(result)).toBe(true);
				}),
		);

		it.effect.prop(
			"fails to decode if Uint8Array is too short",
			[fc.uint8Array({ minLength: 0, maxLength: 4 })],
			([uint8Array]) =>
				Effect.gen(function* () {
					const result = yield* Effect.exit(decodeQuestion(uint8Array));
					expect(Exit.isFailure(result)).toBe(true);
				}),
		);

		it.effect.prop(
			"fails to decode if Uint8Array is too long",
			[fc.uint8Array({ minLength: 261, maxLength: 300 })],
			([uint8Array]) =>
				Effect.gen(function* () {
					const result = yield* Effect.exit(decodeQuestion(uint8Array));
					expect(Exit.isFailure(result)).toBe(true);
				}),
		);

		it.effect.prop(
			"encodeQuestion and decodeQuestion are inverses (roundtrip)",
			[arbitraryDnsQuestionUint8Array],
			([uint8Array]) =>
				Effect.gen(function* () {
					const decoded = yield* decodeQuestion(uint8Array);
					const encoded = yield* encodeQuestion(decoded);
					expect(Array.from(encoded)).toEqual(Array.from(uint8Array));
				}),
		);

		it.effect.prop(
			"decoding then encoding yields a Uint8Array of expected length",
			[arbitraryDnsQuestionUint8Array],
			([uint8Array]) =>
				Effect.gen(function* () {
					const question = yield* decodeQuestion(uint8Array);
					const encoded = yield* encodeQuestion(question);
					expect(encoded.length).toBe(uint8Array.length);
				}),
		);

		it.effect.prop(
			"decoded question has valid qname structure",
			[arbitraryDnsQuestionUint8Array],
			([uint8Array]) =>
				Effect.gen(function* () {
					const question = yield* decodeQuestion(uint8Array);

					// Check that qname is an array
					expect(Array.isArray(question.qname)).toBe(true);

					// Check that each label is a Uint8Array with valid length
					for (const label of question.qname) {
						expect(label instanceof Uint8Array).toBe(true);
						expect(label.length).toBeGreaterThanOrEqual(1);
						expect(label.length).toBeLessThanOrEqual(63);
					}

					// Check that total length is within limits
					const totalLength =
						question.qname.reduce((sum, label) => sum + label.length + 1, 0) +
						1;
					expect(totalLength).toBeLessThanOrEqual(255);
				}),
		);

		it.effect("decodes a simple domain name", () =>
			Effect.gen(function* () {
				const question = new Uint8Array([
					7, // length 7
					101,
					120,
					97,
					109,
					112,
					108,
					101, // "example"
					3, // length 3
					99,
					111,
					109, // "com"
					0, // root label / null terminator
					0,
					1, // QTYPE: A (1)
					0,
					1, // QCLASS: IN (1)
				]);

				const decoded = yield* decodeQuestion(question);

				expect(decoded.qname.length).toBe(2);
				expect(Array.from(decoded.qname[0]!)).toEqual([
					101, 120, 97, 109, 112, 108, 101,
				]); // "example"
				expect(Array.from(decoded.qname[1]!)).toEqual([99, 111, 109]); // "com"
				expect(decoded.qtype).toBe(DnsType.A);
				expect(decoded.qclass).toBe(1);
			}),
		);

		it.effect("encodes a simple domain name", () =>
			Effect.gen(function* () {
				const question = {
					qname: [
						new Uint8Array([101, 120, 97, 109, 112, 108, 101]), // "example"
						new Uint8Array([99, 111, 109]), // "com"
					],
					qtype: DnsType.A,
					qclass: 1,
				};

				const encoded = yield* encodeQuestion(question);

				const expected = new Uint8Array([
					7, // length 7
					101,
					120,
					97,
					109,
					112,
					108,
					101, // "example"
					3, // length 3
					99,
					111,
					109, // "com"
					0, // root label / null terminator
					0,
					1, // QTYPE: A (1)
					0,
					1, // QCLASS: IN (1)
				]);

				expect(Array.from(encoded)).toEqual(Array.from(expected));
			}),
		);

		it.effect("handles single label domain", () =>
			Effect.gen(function* () {
				const question = new Uint8Array([
					9, // length 9
					108,
					111,
					99,
					97,
					108,
					104,
					111,
					115,
					116, // "localhost"
					0, // root label / null terminator
					0,
					1, // QTYPE: A (1)
					0,
					1, // QCLASS: IN (1)
				]);

				const decoded = yield* decodeQuestion(question);

				expect(decoded.qname.length).toBe(1);
				expect(Array.from(decoded.qname[0]!)).toEqual([
					108, 111, 99, 97, 108, 104, 111, 115, 116,
				]); // "localhost"
				expect(decoded.qtype).toBe(DnsType.A);
				expect(decoded.qclass).toBe(1);
			}),
		);

		it.effect("handles maximum label length (63 bytes)", () =>
			Effect.gen(function* () {
				const maxLabel = new Uint8Array(63).fill(97); // 63 'a's
				const question = {
					qname: [maxLabel],
					qtype: DnsType.A,
					qclass: 1,
				};

				const encoded = yield* encodeQuestion(question);
				const decoded = yield* decodeQuestion(encoded);

				expect(decoded.qname.length).toBe(1);
				expect(decoded.qname[0]!.length).toBe(63);
				expect(Array.from(decoded.qname[0]!)).toEqual(Array.from(maxLabel));
			}),
		);

		it.effect("fails on label exceeding 63 bytes during decode", () =>
			Effect.gen(function* () {
				const question = new Uint8Array([
					64, // length 64 (invalid)
					...new Array(64).fill(97), // 64 'a's
					0, // root label / null terminator
					0,
					1, // QTYPE: A (1)
					0,
					1, // QCLASS: IN (1)
				]);

				const result = yield* Effect.exit(decodeQuestion(question));
				expect(Exit.isFailure(result)).toBe(true);
			}),
		);

		it.effect("fails on label exceeding 63 bytes during encode", () =>
			Effect.gen(function* () {
				const question = {
					qname: [new Uint8Array(64).fill(97)], // 64 'a's (invalid)
					qtype: DnsType.A,
					qclass: 1,
				};

				const result = yield* Effect.exit(encodeQuestion(question));
				expect(Exit.isFailure(result)).toBe(true);
			}),
		);
	});

	describe("resource record", () => {
		// Generate a valid TTL (31-bit unsigned integer, 0-padded to 32 bits)
		const arbitraryTtl = fc.integer({ min: 0, max: 0x7fffffff }); // 2^31 - 1

		// Generate a valid RDLENGTH
		const arbitraryRdlength = fc.integer({ min: 0, max: 65535 });

		// Generate RDATA based on rdlength
		const arbitraryRdata = (rdlength: number) =>
			fc.uint8Array({ minLength: rdlength, maxLength: rdlength });

		// Generate a valid resource record structure
		const arbitraryResourceRecord = fc
			.record({
				name: arbitraryDnsName,
				type: arbitraryDnsType,
				class: fc.integer({ min: 0, max: 65535 }),
				ttl: arbitraryTtl,
				rdlength: arbitraryRdlength,
			})
			.chain((record) =>
				arbitraryRdata(record.rdlength).map((rdata) => ({
					...record,
					rdata,
				})),
			);

		// Generate a valid resource record as Uint8Array
		const arbitraryResourceRecordUint8Array = arbitraryResourceRecord.map(
			(record) => {
				// Calculate total length
				const nameLength =
					record.name.reduce((sum, label) => sum + label.length + 1, 0) + 1; // +1 for each length byte, +1 for terminator
				const totalLength = nameLength + 10 + record.rdlength; // 10 bytes for TYPE, CLASS, TTL, RDLENGTH

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

				// Write TYPE (2 bytes)
				dataView.setUint16(offset, record.type, false);
				offset += 2;

				// Write CLASS (2 bytes)
				dataView.setUint16(offset, record.class, false);
				offset += 2;

				// Write TTL (4 bytes, 32-bit with high bit always 0)
				dataView.setUint32(offset, record.ttl, false);
				offset += 4;

				// Write RDLENGTH (2 bytes)
				dataView.setUint16(offset, record.rdlength, false);
				offset += 2;

				// Write RDATA
				buffer.set(record.rdata, offset);

				return buffer;
			},
		);

		it.effect.prop(
			"successfully decodes a Uint8Array to a ResourceRecord",
			[arbitraryResourceRecordUint8Array],
			([uint8Array]) =>
				Effect.gen(function* () {
					const result = yield* Effect.exit(decodeResourceRecord(uint8Array));
					expect(Exit.isSuccess(result)).toBe(true);
				}),
		);

		it.effect.prop(
			"decoded resource record has valid structure",
			[arbitraryResourceRecordUint8Array],
			([uint8Array]) =>
				Effect.gen(function* () {
					const record = yield* decodeResourceRecord(uint8Array);

					// Check name is an array
					expect(Array.isArray(record.name)).toBe(true);

					// Check each label in name
					for (const label of record.name) {
						expect(label instanceof Uint8Array).toBe(true);
						expect(label.length).toBeGreaterThanOrEqual(1);
						expect(label.length).toBeLessThanOrEqual(63);
					}

					// Check TTL is 31-bit unsigned (high bit is 0)
					expect(record.ttl).toBeGreaterThanOrEqual(0);
					expect(record.ttl).toBeLessThanOrEqual(0x7fffffff);

					// Check rdlength matches rdata length
					expect(record.rdata.length).toBe(record.rdlength);
				}),
		);

		it.effect.prop(
			"fails to decode if TTL has high bit set (not 31-bit)",
			[arbitraryResourceRecordUint8Array],
			([uint8Array]) =>
				Effect.gen(function* () {
					// Find TTL offset (after name, type, class)
					let nameEndOffset = 0;
					while (uint8Array[nameEndOffset] !== 0) {
						const labelLength = uint8Array[nameEndOffset];
						nameEndOffset += labelLength + 1;
					}
					nameEndOffset += 1; // skip null terminator
					const ttlOffset = nameEndOffset + 4; // skip TYPE and CLASS

					// Create a copy and set high bit of TTL
					const modifiedArray = new Uint8Array(uint8Array);
					const dataView = new DataView(modifiedArray.buffer);
					const originalTtl = dataView.getUint32(ttlOffset, false);
					const invalidTtl = originalTtl | 0x80000000; // Set high bit
					dataView.setUint32(ttlOffset, invalidTtl, false);

					const result = yield* Effect.exit(
						decodeResourceRecord(modifiedArray),
					);
					expect(Exit.isFailure(result)).toBe(true);
				}),
		);

		it.effect("decodes a simple A record", () =>
			Effect.gen(function* () {
				const record = new Uint8Array([
					7, // length 7
					101,
					120,
					97,
					109,
					112,
					108,
					101, // "example"
					3, // length 3
					99,
					111,
					109, // "com"
					0, // root label / null terminator
					0,
					1, // TYPE: A (1)
					0,
					1, // CLASS: IN (1)
					0,
					0,
					0,
					60, // TTL: 60 seconds
					0,
					4, // RDLENGTH: 4 bytes
					192,
					0,
					2,
					1, // RDATA: 192.0.2.1
				]);

				const decoded = yield* decodeResourceRecord(record);

				expect(decoded.name.length).toBe(2);
				expect(Array.from(decoded.name[0]!)).toEqual([
					101, 120, 97, 109, 112, 108, 101,
				]); // "example"
				expect(Array.from(decoded.name[1]!)).toEqual([99, 111, 109]); // "com"
				expect(decoded.type).toBe(DnsType.A);
				expect(decoded.class).toBe(1);
				expect(decoded.ttl).toBe(60);
				expect(decoded.rdlength).toBe(4);
				expect(Array.from(decoded.rdata)).toEqual([192, 0, 2, 1]);
			}),
		);

		it.effect("handles zero TTL", () =>
			Effect.gen(function* () {
				const record = new Uint8Array([
					4, // length 4
					116,
					101,
					115,
					116, // "test"
					0, // root label / null terminator
					0,
					1, // TYPE: A (1)
					0,
					1, // CLASS: IN (1)
					0,
					0,
					0,
					0, // TTL: 0 (no caching)
					0,
					4, // RDLENGTH: 4 bytes
					10,
					0,
					0,
					1, // RDATA: 10.0.0.1
				]);

				const decoded = yield* decodeResourceRecord(record);
				expect(decoded.ttl).toBe(0);
			}),
		);

		it.effect("handles maximum TTL (2^31 - 1)", () =>
			Effect.gen(function* () {
				const record = new Uint8Array([
					4, // length 4
					116,
					101,
					115,
					116, // "test"
					0, // root label / null terminator
					0,
					15, // TYPE: MX (15)
					0,
					1, // CLASS: IN (1)
					0x7f,
					0xff,
					0xff,
					0xff, // TTL: 2147483647 (max 31-bit value)
					0,
					2, // RDLENGTH: 2 bytes
					0,
					10, // RDATA: priority 10
				]);

				const decoded = yield* decodeResourceRecord(record);
				expect(decoded.ttl).toBe(0x7fffffff);
			}),
		);

		it.effect.prop(
			"correctly extracts RDATA of specified length",
			[
				fc.record({
					name: arbitraryDnsName,
					rdlength: fc.integer({ min: 0, max: 100 }),
				}),
			],
			([{ name, rdlength }]) =>
				Effect.gen(function* () {
					// Build a resource record with specific RDATA
					const nameLength =
						name.reduce((sum, label) => sum + label.length + 1, 0) + 1;
					const totalLength = nameLength + 10 + rdlength;

					const buffer = new Uint8Array(totalLength);
					const dataView = new DataView(buffer.buffer);
					let offset = 0;

					// Write name
					for (const label of name) {
						buffer[offset++] = label.length;
						buffer.set(label, offset);
						offset += label.length;
					}
					buffer[offset++] = 0;

					// Write fixed fields
					dataView.setUint16(offset, DnsType.TXT, false);
					offset += 2;
					dataView.setUint16(offset, 1, false); // CLASS IN
					offset += 2;
					dataView.setUint32(offset, 3600, false); // TTL
					offset += 4;
					dataView.setUint16(offset, rdlength, false);
					offset += 2;

					// Write RDATA with pattern
					for (let i = 0; i < rdlength; i++) {
						buffer[offset + i] = i % 256;
					}

					const decoded = yield* decodeResourceRecord(buffer);
					expect(decoded.rdlength).toBe(rdlength);
					expect(decoded.rdata.length).toBe(rdlength);

					// Verify RDATA pattern
					for (let i = 0; i < rdlength; i++) {
						expect(decoded.rdata[i]).toBe(i % 256);
					}
				}),
		);
	});
});
