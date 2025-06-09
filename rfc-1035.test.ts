import { describe, expect, it } from "@effect/vitest";
import { Effect, Exit, FastCheck as fc } from "effect";
import {
	decodeHeader,
	encodeHeader,
	decodeQuestion,
	encodeQuestion,
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
});
