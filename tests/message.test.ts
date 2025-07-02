import { describe, expect, it } from "@effect/vitest";
import { Effect, Exit, Schema } from "effect";
import { MessageFromUint8Array } from "../src/message";
import { RRTypeNameToRRType } from "../src";
import {
	arbitraryValidDnsMessageUint8Array,
	arbitraryCommonDnsMessage,
	arbitraryInvalidDnsHeaderUint8Array,
} from "./arbitraries";

describe("message", () => {
	it.effect.prop(
		"successfully decodes valid DNS messages",
		[arbitraryValidDnsMessageUint8Array],
		([{ messageBuffer, header, question }]) =>
			Effect.gen(function* () {
				const result = yield* Effect.exit(
					Schema.decode(MessageFromUint8Array)(messageBuffer),
				);

				expect(Exit.isSuccess(result)).toBe(true);

				if (Exit.isSuccess(result)) {
					const message = result.value;

					// Validate header fields
					expect(message.header.id).toBe(header.id);
					expect(message.header.qr).toBe(header.qr);
					expect(message.header.opcode).toBe(header.opcode);
					expect(message.header.aa).toBe(header.aa);
					expect(message.header.tc).toBe(header.tc);
					expect(message.header.rd).toBe(header.rd);
					expect(message.header.ra).toBe(header.ra);
					expect(message.header.z).toBe(header.z);
					expect(message.header.rcode).toBe(header.rcode);
					expect(message.header.qdcount).toBe(header.qdcount);
					expect(message.header.ancount).toBe(header.ancount);
					expect(message.header.nscount).toBe(header.nscount);
					expect(message.header.arcount).toBe(header.arcount);

					// Validate question fields
					expect(message.question.qname.labels).toHaveLength(
						question.qname.length,
					);
					for (let i = 0; i < question.qname.length; i++) {
						expect(Array.from(message.question.qname.labels[i]!)).toEqual(
							Array.from(question.qname[i]!),
						);
					}
					expect(message.question.qtype).toBe(question.qtype);
					expect(message.question.qclass).toBe(question.qclass);
				}
			}),
	);

	it.effect.prop(
		"successfully decodes common DNS message patterns",
		[arbitraryCommonDnsMessage],
		([{ messageBuffer, header, question }]) =>
			Effect.gen(function* () {
				const result = yield* Effect.exit(
					Schema.decode(MessageFromUint8Array)(messageBuffer),
				);

				expect(Exit.isSuccess(result)).toBe(true);

				if (Exit.isSuccess(result)) {
					const message = result.value;

					// Validate that common patterns decode correctly
					expect(message.header.id).toBe(header.id);
					expect(message.header.qr).toBe(0); // All common messages are queries
					expect(message.header.qdcount).toBe(1); // All have one question
					expect(message.header.ancount).toBe(0); // No answers
					expect(message.header.z).toBe(0); // RFC compliance

					// Validate question matches expected pattern
					expect(message.question.qtype).toBe(question.qtype);
					expect(message.question.qclass).toBe(question.qclass);
					expect(message.question.qname.labels).toHaveLength(
						question.qname.length,
					);
				}
			}),
	);

	it.effect("successfully decodes specific test cases", () =>
		Effect.gen(function* () {
			// Test case 1: A record query for example.com
			const exampleComMessage = new Uint8Array([
				// Header (12 bytes)
				0x30,
				0x39, // ID: 12345
				0x01,
				0x00, // Flags: QR=0, OPCODE=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0
				0x00,
				0x01, // QDCOUNT: 1
				0x00,
				0x00, // ANCOUNT: 0
				0x00,
				0x00, // NSCOUNT: 0
				0x00,
				0x00, // ARCOUNT: 0
				// Question
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
				0x00, // terminator
				0x00,
				0x01, // QTYPE: A (1)
				0x00,
				0x01, // QCLASS: IN (1)
			]);

			const result = yield* Effect.exit(
				Schema.decode(MessageFromUint8Array)(exampleComMessage),
			);

			expect(Exit.isSuccess(result)).toBe(true);

			if (Exit.isSuccess(result)) {
				const message = result.value;
				expect(message.header.id).toBe(12345);
				expect(message.header.qr).toBe(0);
				expect(message.header.rd).toBe(1);
				expect(message.question.qname.labels).toHaveLength(2);
				expect(Array.from(message.question.qname.labels[0]!)).toEqual([
					101,
					120,
					97,
					109,
					112,
					108,
					101, // "example"
				]);
				expect(Array.from(message.question.qname.labels[1]!)).toEqual([
					99,
					111,
					109, // "com"
				]);
				expect(message.question.qtype).toBe(RRTypeNameToRRType.A);
				expect(message.question.qclass).toBe(1);
			}
		}),
	);

	it.effect("successfully decodes localhost queries", () =>
		Effect.gen(function* () {
			// Test case: A record query for localhost
			const localhostMessage = new Uint8Array([
				// Header (12 bytes)
				0xd4,
				0x31, // ID: 54321
				0x00,
				0x00, // Flags: QR=0, OPCODE=0, AA=0, TC=0, RD=0, RA=0, Z=0, RCODE=0
				0x00,
				0x01, // QDCOUNT: 1
				0x00,
				0x00, // ANCOUNT: 0
				0x00,
				0x00, // NSCOUNT: 0
				0x00,
				0x00, // ARCOUNT: 0
				// Question
				0x09,
				0x6c,
				0x6f,
				0x63,
				0x61,
				0x6c,
				0x68,
				0x6f,
				0x73,
				0x74, // "localhost"
				0x00, // terminator
				0x00,
				0x01, // QTYPE: AAAA (28)
				0x00,
				0x01, // QCLASS: IN (1)
			]);

			const result = yield* Effect.exit(
				Schema.decode(MessageFromUint8Array)(localhostMessage),
			);

			expect(Exit.isSuccess(result)).toBe(true);

			if (Exit.isSuccess(result)) {
				const message = result.value;
				expect(message.header.id).toBe(54321);
				expect(message.header.rd).toBe(0);
				expect(message.question.qname.labels).toHaveLength(1);
				expect(Array.from(message.question.qname.labels[0]!)).toEqual([
					108,
					111,
					99,
					97,
					108,
					104,
					111,
					115,
					116, // "localhost"
				]);
				expect(message.question.qtype).toBe(RRTypeNameToRRType.A);
			}
		}),
	);

	it.effect("handles various QTYPE values correctly", () =>
		Effect.gen(function* () {
			const qtypeTests = [
				{ qtype: RRTypeNameToRRType.A, bytes: [0x00, 0x01] },
				{ qtype: RRTypeNameToRRType.NS, bytes: [0x00, 0x02] },
				{ qtype: RRTypeNameToRRType.CNAME, bytes: [0x00, 0x05] },
				{ qtype: RRTypeNameToRRType.MX, bytes: [0x00, 0x0f] },
				{ qtype: RRTypeNameToRRType.TXT, bytes: [0x00, 0x10] },
			];

			for (const { qtype, bytes } of qtypeTests) {
				const message = new Uint8Array([
					// Header
					0x12,
					0x34, // ID
					0x01,
					0x00, // Flags
					0x00,
					0x01, // QDCOUNT: 1
					0x00,
					0x00,
					0x00,
					0x00,
					0x00,
					0x00, // Other counts: 0
					// Question: test.example.com
					0x04,
					0x74,
					0x65,
					0x73,
					0x74, // "test"
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
					0x00, // terminator
					...bytes, // QTYPE
					0x00,
					0x01, // QCLASS: IN
				]);

				const result = yield* Effect.exit(
					Schema.decode(MessageFromUint8Array)(message),
				);

				expect(Exit.isSuccess(result)).toBe(true);

				if (Exit.isSuccess(result)) {
					expect(result.value.question.qtype).toBe(qtype);
				}
			}
		}),
	);

	// // Error cases using arbitraries
	it.effect("fails on message too small for header", () =>
		Effect.gen(function* () {
			const tooSmall = new Uint8Array(11); // Header needs 12 bytes

			const result = yield* Effect.exit(
				Schema.decode(MessageFromUint8Array)(tooSmall),
			);

			expect(Exit.isFailure(result)).toBe(true);
		}),
	);
	//
	it.effect("fails on message too small for question", () =>
		Effect.gen(function* () {
			// Valid header but no room for question
			const headerOnly = new Uint8Array(16); // 12 bytes header + 4 partial question

			// Fill header with valid data
			const headerView = new DataView(headerOnly.buffer);
			headerView.setUint16(0, 12345, false); // ID
			headerView.setUint8(2, 0x01); // RD=1
			headerView.setUint8(3, 0x00); // Other flags = 0
			headerView.setUint16(4, 1, false); // QDCOUNT=1

			const result = yield* Effect.exit(
				Schema.decode(MessageFromUint8Array)(headerOnly),
			);

			expect(Exit.isFailure(result)).toBe(true);
		}),
	);

	it.effect.prop(
		"fails on invalid header data",
		[arbitraryInvalidDnsHeaderUint8Array],
		([invalidHeaderBytes]) =>
			Effect.gen(function* () {
				// Add a minimal valid question to the invalid header
				const validQuestion = new Uint8Array([
					0x04,
					0x74,
					0x65,
					0x73,
					0x74, // "test"
					0x00, // terminator
					0x00,
					0x01, // QTYPE: A
					0x00,
					0x01, // QCLASS: IN
				]);

				const message = new Uint8Array(
					invalidHeaderBytes.length + validQuestion.length,
				);
				message.set(invalidHeaderBytes, 0);
				message.set(validQuestion, invalidHeaderBytes.length);

				const result = yield* Effect.exit(
					Schema.decode(MessageFromUint8Array)(message),
				);

				expect(Exit.isFailure(result)).toBe(true);
			}),
	);

	it.effect("fails on invalid question data", () =>
		Effect.gen(function* () {
			// Valid header with invalid question (label too long)
			const header = new Uint8Array(12);
			const headerView = new DataView(header.buffer);

			headerView.setUint16(0, 12345, false); // ID
			headerView.setUint8(2, 0x01); // RD=1
			headerView.setUint8(3, 0x00); // Other flags = 0
			headerView.setUint16(4, 1, false); // QDCOUNT=1

			// Invalid question with label length > 63
			const invalidQuestion = new Uint8Array(70);
			invalidQuestion[0] = 64; // Invalid length > 63
			// Fill with valid characters
			for (let i = 1; i < 65; i++) {
				invalidQuestion[i] = 65; // 'A'
			}
			invalidQuestion[65] = 0; // terminator
			// Add QTYPE and QCLASS
			const questionView = new DataView(invalidQuestion.buffer);
			questionView.setUint16(66, 1, false); // A record
			questionView.setUint16(68, 1, false); // IN class

			const message = new Uint8Array(header.length + invalidQuestion.length);
			message.set(header, 0);
			message.set(invalidQuestion, header.length);

			const result = yield* Effect.exit(
				Schema.decode(MessageFromUint8Array)(message),
			);

			expect(Exit.isFailure(result)).toBe(true);
		}),
	);

	it.effect("handles maximum length domain names", () =>
		Effect.gen(function* () {
			// Create a domain name approaching the 255-byte limit
			const maxLabel = new Uint8Array(63).fill(97); // 63 'a's
			const message = new Uint8Array([
				// Header
				0x12,
				0x34, // ID
				0x01,
				0x00, // Flags
				0x00,
				0x01, // QDCOUNT: 1
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00, // Other counts: 0
				// Question with three 63-byte labels + "test"
				63,
				...maxLabel, // First 63-byte label
				63,
				...maxLabel, // Second 63-byte label
				63,
				...maxLabel, // Third 63-byte label
				4,
				116,
				101,
				115,
				116, // "test"
				0, // terminator
				0x00,
				0x01, // QTYPE: A
				0x00,
				0x01, // QCLASS: IN
			]);

			const result = yield* Effect.exit(
				Schema.decode(MessageFromUint8Array)(message),
			);

			expect(Exit.isSuccess(result)).toBe(true);

			if (Exit.isSuccess(result)) {
				const decodedMessage = result.value;
				expect(decodedMessage.question.qname.labels).toHaveLength(4);
				expect(decodedMessage.question.qname.labels[0]!.length).toBe(63);
				expect(decodedMessage.question.qname.labels[1]!.length).toBe(63);
				expect(decodedMessage.question.qname.labels[2]!.length).toBe(63);
				expect(decodedMessage.question.qname.labels[3]!.length).toBe(4);
			}
		}),
	);

	it.effect("handles different header flag combinations", () =>
		Effect.gen(function* () {
			const flagCombinations = [
				{ qr: 0, opcode: 0, rd: 0, byte2: 0x00, byte3: 0x00 },
				{ qr: 0, opcode: 0, rd: 1, byte2: 0x01, byte3: 0x00 },
				{ qr: 0, opcode: 1, rd: 0, byte2: 0x08, byte3: 0x00 },
				{ qr: 0, opcode: 2, rd: 0, byte2: 0x10, byte3: 0x00 },
			];

			for (const flags of flagCombinations) {
				const message = new Uint8Array([
					// Header
					0x12,
					0x34, // ID
					flags.byte2,
					flags.byte3, // Flags
					0x00,
					0x01, // QDCOUNT: 1
					0x00,
					0x00,
					0x00,
					0x00,
					0x00,
					0x00, // Other counts: 0
					// Question: test.com
					0x04,
					0x74,
					0x65,
					0x73,
					0x74, // "test"
					0x03,
					0x63,
					0x6f,
					0x6d, // "com"
					0x00, // terminator
					0x00,
					0x01, // QTYPE: A
					0x00,
					0x01, // QCLASS: IN
				]);

				const result = yield* Effect.exit(
					Schema.decode(MessageFromUint8Array)(message),
				);

				expect(Exit.isSuccess(result)).toBe(true);

				if (Exit.isSuccess(result)) {
					const decodedMessage = result.value;
					expect(decodedMessage.header.qr).toBe(flags.qr);
					expect(decodedMessage.header.opcode).toBe(flags.opcode);
					expect(decodedMessage.header.rd).toBe(flags.rd);
				}
			}
		}),
	);
});

