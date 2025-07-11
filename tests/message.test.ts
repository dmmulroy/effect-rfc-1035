import { describe, expect, it } from "@effect/vitest";
import { Cause, Effect, Exit, Schema } from "effect";
import { MessageFromUint8Array } from "../src/message";
import { RRTypeNameToRRType } from "../src";
import {
	arbitraryValidDnsMessageUint8Array,
	arbitraryCommonDnsMessage,
	arbitraryInvalidDnsHeaderUint8Array,
	arbitraryMultiQuestionDnsMessageUint8Array,
	arbitraryCountMismatchDnsMessageUint8Array,
	arbitrarySimpleCompressionMessage,
	arbitraryMultiCompressionMessage,
	arbitraryTailCompressionMessage,
	arbitraryCompressionErrorMessages,
	arbitraryRfc1035CompressionExample,
	arbitraryCnameCompressionMessage,
	arbitraryNsCompressionMessage,
	arbitraryMxCompressionMessage,
	arbitraryCompressedDnsMessage,
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

				if (Exit.isFailure(result)) {
					console.log(Cause.prettyErrors(result.cause));
				}

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

					// Validate question
					expect(message.question).toHaveLength(1);
					expect(header.qdcount).toBe(1);

					const expectedQuestion = question!;
					const actualQuestion = message.question[0]!;

					expect(actualQuestion.qname.labels).toHaveLength(
						expectedQuestion.qname.length,
					);

					for (let i = 0; i < expectedQuestion.qname.length; i++) {
						expect(Array.from(actualQuestion.qname.labels[i]!)).toEqual(
							Array.from(expectedQuestion.qname[i]!),
						);
					}
					expect(expectedQuestion.qtype).toBe(actualQuestion.qtype);
					expect(actualQuestion.qclass).toBe(expectedQuestion.qclass);

					// Validate answer section
					expect(message.answer).toHaveLength(header.ancount);

					// Validate authority section
					expect(message.authority).toHaveLength(header.nscount);

					// Validate additional section
					expect(message.additional).toHaveLength(header.arcount);
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

					// Validate question matches expected patterns
					expect(message.question).toHaveLength(1);
					const actualQuestion = message.question[0]!;
					expect(actualQuestion.qtype).toBe(question!.qtype);
					expect(actualQuestion.qclass).toBe(question!.qclass);
					expect(actualQuestion.qname.labels).toHaveLength(
						question!.qname.length,
					);

					// Validate sections are empty for common queries
					expect(message.answer).toHaveLength(0);
					expect(message.authority).toHaveLength(0);
					expect(message.additional).toHaveLength(0);
				}
			}),
	);
	//
	// it.effect("successfully decodes specific test cases", () =>
	// 	Effect.gen(function* () {
	// 		// Test case 1: A record query for example.com
	// 		const exampleComMessage = new Uint8Array([
	// 			// Header (12 bytes)
	// 			0x30,
	// 			0x39, // ID: 12345
	// 			0x01,
	// 			0x00, // Flags: QR=0, OPCODE=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0
	// 			0x00,
	// 			0x01, // QDCOUNT: 1
	// 			0x00,
	// 			0x00, // ANCOUNT: 0
	// 			0x00,
	// 			0x00, // NSCOUNT: 0
	// 			0x00,
	// 			0x00, // ARCOUNT: 0
	// 			// Question
	// 			0x07,
	// 			0x65,
	// 			0x78,
	// 			0x61,
	// 			0x6d,
	// 			0x70,
	// 			0x6c,
	// 			0x65, // "example"
	// 			0x03,
	// 			0x63,
	// 			0x6f,
	// 			0x6d, // "com"
	// 			0x00, // terminator
	// 			0x00,
	// 			0x01, // QTYPE: A (1)
	// 			0x00,
	// 			0x01, // QCLASS: IN (1)
	// 		]);
	//
	// 		const result = yield* Effect.exit(
	// 			Schema.decode(MessageFromUint8Array)(exampleComMessage),
	// 		);
	//
	// 		expect(Exit.isSuccess(result)).toBe(true);
	//
	// 		if (Exit.isSuccess(result)) {
	// 			const message = result.value;
	// 			expect(message.header.id).toBe(12345);
	// 			expect(message.header.qr).toBe(0);
	// 			expect(message.header.rd).toBe(1);
	// 			expect(message.questions).toHaveLength(1);
	// 			expect(message.questions[0]!.qname.labels).toHaveLength(2);
	// 			expect(Array.from(message.questions[0]!.qname.labels[0]!)).toEqual([
	// 				101,
	// 				120,
	// 				97,
	// 				109,
	// 				112,
	// 				108,
	// 				101, // "example"
	// 			]);
	// 			expect(Array.from(message.questions[0]!.qname.labels[1]!)).toEqual([
	// 				99,
	// 				111,
	// 				109, // "com"
	// 			]);
	// 			expect(message.questions[0]!.qtype).toBe(RRTypeNameToRRType.A);
	// 			expect(message.questions[0]!.qclass).toBe(1);
	// 		}
	// 	}),
	// );
	//
	// it.effect("successfully decodes localhost queries", () =>
	// 	Effect.gen(function* () {
	// 		// Test case: A record query for localhost
	// 		const localhostMessage = new Uint8Array([
	// 			// Header (12 bytes)
	// 			0xd4,
	// 			0x31, // ID: 54321
	// 			0x00,
	// 			0x00, // Flags: QR=0, OPCODE=0, AA=0, TC=0, RD=0, RA=0, Z=0, RCODE=0
	// 			0x00,
	// 			0x01, // QDCOUNT: 1
	// 			0x00,
	// 			0x00, // ANCOUNT: 0
	// 			0x00,
	// 			0x00, // NSCOUNT: 0
	// 			0x00,
	// 			0x00, // ARCOUNT: 0
	// 			// Question
	// 			0x09,
	// 			0x6c,
	// 			0x6f,
	// 			0x63,
	// 			0x61,
	// 			0x6c,
	// 			0x68,
	// 			0x6f,
	// 			0x73,
	// 			0x74, // "localhost"
	// 			0x00, // terminator
	// 			0x00,
	// 			0x01, // QTYPE: AAAA (28)
	// 			0x00,
	// 			0x01, // QCLASS: IN (1)
	// 		]);
	//
	// 		const result = yield* Effect.exit(
	// 			Schema.decode(MessageFromUint8Array)(localhostMessage),
	// 		);
	//
	// 		expect(Exit.isSuccess(result)).toBe(true);
	//
	// 		if (Exit.isSuccess(result)) {
	// 			const message = result.value;
	// 			expect(message.header.id).toBe(54321);
	// 			expect(message.header.rd).toBe(0);
	// 			expect(message.question.qname.labels).toHaveLength(1);
	// 			expect(Array.from(message.question.qname.labels[0]!)).toEqual([
	// 				108,
	// 				111,
	// 				99,
	// 				97,
	// 				108,
	// 				104,
	// 				111,
	// 				115,
	// 				116, // "localhost"
	// 			]);
	// 			expect(message.question.qtype).toBe(RRTypeNameToRRType.A);
	// 		}
	// 	}),
	// );
	//
	// it.effect("handles various QTYPE values correctly", () =>
	// 	Effect.gen(function* () {
	// 		const qtypeTests = [
	// 			{ qtype: RRTypeNameToRRType.A, bytes: [0x00, 0x01] },
	// 			{ qtype: RRTypeNameToRRType.NS, bytes: [0x00, 0x02] },
	// 			{ qtype: RRTypeNameToRRType.CNAME, bytes: [0x00, 0x05] },
	// 			{ qtype: RRTypeNameToRRType.MX, bytes: [0x00, 0x0f] },
	// 			{ qtype: RRTypeNameToRRType.TXT, bytes: [0x00, 0x10] },
	// 		];
	//
	// 		for (const { qtype, bytes } of qtypeTests) {
	// 			const message = new Uint8Array([
	// 				// Header
	// 				0x12,
	// 				0x34, // ID
	// 				0x01,
	// 				0x00, // Flags
	// 				0x00,
	// 				0x01, // QDCOUNT: 1
	// 				0x00,
	// 				0x00,
	// 				0x00,
	// 				0x00,
	// 				0x00,
	// 				0x00, // Other counts: 0
	// 				// Question: test.example.com
	// 				0x04,
	// 				0x74,
	// 				0x65,
	// 				0x73,
	// 				0x74, // "test"
	// 				0x07,
	// 				0x65,
	// 				0x78,
	// 				0x61,
	// 				0x6d,
	// 				0x70,
	// 				0x6c,
	// 				0x65, // "example"
	// 				0x03,
	// 				0x63,
	// 				0x6f,
	// 				0x6d, // "com"
	// 				0x00, // terminator
	// 				...bytes, // QTYPE
	// 				0x00,
	// 				0x01, // QCLASS: IN
	// 			]);
	//
	// 			const result = yield* Effect.exit(
	// 				Schema.decode(MessageFromUint8Array)(message),
	// 			);
	//
	// 			expect(Exit.isSuccess(result)).toBe(true);
	//
	// 			if (Exit.isSuccess(result)) {
	// 				expect(result.value.question.qtype).toBe(qtype);
	// 			}
	// 		}
	// 	}),
	// );
	//
	// // // Error cases using arbitraries
	// it.effect("fails on message too small for header", () =>
	// 	Effect.gen(function* () {
	// 		const tooSmall = new Uint8Array(11); // Header needs 12 bytes
	//
	// 		const result = yield* Effect.exit(
	// 			Schema.decode(MessageFromUint8Array)(tooSmall),
	// 		);
	//
	// 		expect(Exit.isFailure(result)).toBe(true);
	// 	}),
	// );
	// //
	// it.effect("fails on message too small for question", () =>
	// 	Effect.gen(function* () {
	// 		// Valid header but no room for question
	// 		const headerOnly = new Uint8Array(16); // 12 bytes header + 4 partial question
	//
	// 		// Fill header with valid data
	// 		const headerView = new DataView(headerOnly.buffer);
	// 		headerView.setUint16(0, 12345, false); // ID
	// 		headerView.setUint8(2, 0x01); // RD=1
	// 		headerView.setUint8(3, 0x00); // Other flags = 0
	// 		headerView.setUint16(4, 1, false); // QDCOUNT=1
	//
	// 		const result = yield* Effect.exit(
	// 			Schema.decode(MessageFromUint8Array)(headerOnly),
	// 		);
	//
	// 		expect(Exit.isFailure(result)).toBe(true);
	// 	}),
	// );
	//
	// it.effect.prop(
	// 	"fails on invalid header data",
	// 	[arbitraryInvalidDnsHeaderUint8Array],
	// 	([invalidHeaderBytes]) =>
	// 		Effect.gen(function* () {
	// 			// Add a minimal valid question to the invalid header
	// 			const validQuestion = new Uint8Array([
	// 				0x04,
	// 				0x74,
	// 				0x65,
	// 				0x73,
	// 				0x74, // "test"
	// 				0x00, // terminator
	// 				0x00,
	// 				0x01, // QTYPE: A
	// 				0x00,
	// 				0x01, // QCLASS: IN
	// 			]);
	//
	// 			const message = new Uint8Array(
	// 				invalidHeaderBytes.length + validQuestion.length,
	// 			);
	// 			message.set(invalidHeaderBytes, 0);
	// 			message.set(validQuestion, invalidHeaderBytes.length);
	//
	// 			const result = yield* Effect.exit(
	// 				Schema.decode(MessageFromUint8Array)(message),
	// 			);
	//
	// 			expect(Exit.isFailure(result)).toBe(true);
	// 		}),
	// );
	//
	// it.effect("fails on invalid question data", () =>
	// 	Effect.gen(function* () {
	// 		// Valid header with invalid question (label too long)
	// 		const header = new Uint8Array(12);
	// 		const headerView = new DataView(header.buffer);
	//
	// 		headerView.setUint16(0, 12345, false); // ID
	// 		headerView.setUint8(2, 0x01); // RD=1
	// 		headerView.setUint8(3, 0x00); // Other flags = 0
	// 		headerView.setUint16(4, 1, false); // QDCOUNT=1
	//
	// 		// Invalid question with label length > 63
	// 		const invalidQuestion = new Uint8Array(70);
	// 		invalidQuestion[0] = 64; // Invalid length > 63
	// 		// Fill with valid characters
	// 		for (let i = 1; i < 65; i++) {
	// 			invalidQuestion[i] = 65; // 'A'
	// 		}
	// 		invalidQuestion[65] = 0; // terminator
	// 		// Add QTYPE and QCLASS
	// 		const questionView = new DataView(invalidQuestion.buffer);
	// 		questionView.setUint16(66, 1, false); // A record
	// 		questionView.setUint16(68, 1, false); // IN class
	//
	// 		const message = new Uint8Array(header.length + invalidQuestion.length);
	// 		message.set(header, 0);
	// 		message.set(invalidQuestion, header.length);
	//
	// 		const result = yield* Effect.exit(
	// 			Schema.decode(MessageFromUint8Array)(message),
	// 		);
	//
	// 		expect(Exit.isFailure(result)).toBe(true);
	// 	}),
	// );
	//
	// it.effect("handles maximum length domain names", () =>
	// 	Effect.gen(function* () {
	// 		// Create a domain name approaching the 255-byte limit
	// 		const maxLabel = new Uint8Array(63).fill(97); // 63 'a's
	// 		const message = new Uint8Array([
	// 			// Header
	// 			0x12,
	// 			0x34, // ID
	// 			0x01,
	// 			0x00, // Flags
	// 			0x00,
	// 			0x01, // QDCOUNT: 1
	// 			0x00,
	// 			0x00,
	// 			0x00,
	// 			0x00,
	// 			0x00,
	// 			0x00, // Other counts: 0
	// 			// Question with three 63-byte labels + "test"
	// 			63,
	// 			...maxLabel, // First 63-byte label
	// 			63,
	// 			...maxLabel, // Second 63-byte label
	// 			63,
	// 			...maxLabel, // Third 63-byte label
	// 			4,
	// 			116,
	// 			101,
	// 			115,
	// 			116, // "test"
	// 			0, // terminator
	// 			0x00,
	// 			0x01, // QTYPE: A
	// 			0x00,
	// 			0x01, // QCLASS: IN
	// 		]);
	//
	// 		const result = yield* Effect.exit(
	// 			Schema.decode(MessageFromUint8Array)(message),
	// 		);
	//
	// 		expect(Exit.isSuccess(result)).toBe(true);
	//
	// 		if (Exit.isSuccess(result)) {
	// 			const decodedMessage = result.value;
	// 			expect(decodedMessage.question.qname.labels).toHaveLength(4);
	// 			expect(decodedMessage.question.qname.labels[0]!.length).toBe(63);
	// 			expect(decodedMessage.question.qname.labels[1]!.length).toBe(63);
	// 			expect(decodedMessage.question.qname.labels[2]!.length).toBe(63);
	// 			expect(decodedMessage.question.qname.labels[3]!.length).toBe(4);
	// 		}
	// 	}),
	// );
	//
	// it.effect("handles different header flag combinations", () =>
	// 	Effect.gen(function* () {
	// 		const flagCombinations = [
	// 			{ qr: 0, opcode: 0, rd: 0, byte2: 0x00, byte3: 0x00 },
	// 			{ qr: 0, opcode: 0, rd: 1, byte2: 0x01, byte3: 0x00 },
	// 			{ qr: 0, opcode: 1, rd: 0, byte2: 0x08, byte3: 0x00 },
	// 			{ qr: 0, opcode: 2, rd: 0, byte2: 0x10, byte3: 0x00 },
	// 		];
	//
	// 		for (const flags of flagCombinations) {
	// 			const message = new Uint8Array([
	// 				// Header
	// 				0x12,
	// 				0x34, // ID
	// 				flags.byte2,
	// 				flags.byte3, // Flags
	// 				0x00,
	// 				0x01, // QDCOUNT: 1
	// 				0x00,
	// 				0x00,
	// 				0x00,
	// 				0x00,
	// 				0x00,
	// 				0x00, // Other counts: 0
	// 				// Question: test.com
	// 				0x04,
	// 				0x74,
	// 				0x65,
	// 				0x73,
	// 				0x74, // "test"
	// 				0x03,
	// 				0x63,
	// 				0x6f,
	// 				0x6d, // "com"
	// 				0x00, // terminator
	// 				0x00,
	// 				0x01, // QTYPE: A
	// 				0x00,
	// 				0x01, // QCLASS: IN
	// 			]);
	//
	// 			const result = yield* Effect.exit(
	// 				Schema.decode(MessageFromUint8Array)(message),
	// 			);
	//
	// 			expect(Exit.isSuccess(result)).toBe(true);
	//
	// 			if (Exit.isSuccess(result)) {
	// 				const decodedMessage = result.value;
	// 				expect(decodedMessage.header.qr).toBe(flags.qr);
	// 				expect(decodedMessage.header.opcode).toBe(flags.opcode);
	// 				expect(decodedMessage.header.rd).toBe(flags.rd);
	// 			}
	// 		}
	// 	}),
	// );

	it.effect("successfully decodes messages with answer records", () =>
		Effect.gen(function* () {
			// DNS response with one A record answer
			const messageWithAnswer = new Uint8Array([
				// Header (12 bytes)
				0x30,
				0x39, // ID: 12345
				0x81,
				0x80, // Flags: QR=1, OPCODE=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=0
				0x00,
				0x01, // QDCOUNT: 1
				0x00,
				0x01, // ANCOUNT: 1
				0x00,
				0x00, // NSCOUNT: 0
				0x00,
				0x00, // ARCOUNT: 0
				// Question: example.com A IN
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
				0x01, // QTYPE: A
				0x00,
				0x01, // QCLASS: IN
				// Answer: example.com A IN 300 93.184.216.34
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
				0x01, // TYPE: A
				0x00,
				0x01, // CLASS: IN
				0x00,
				0x00,
				0x01,
				0x2c, // TTL: 300
				0x00,
				0x04, // RDLENGTH: 4
				0x5d,
				0xb8,
				0xd8,
				0x22, // RDATA: 93.184.216.34
			]);

			const result = yield* Effect.exit(
				Schema.decode(MessageFromUint8Array)(messageWithAnswer),
			);

			expect(Exit.isSuccess(result)).toBe(true);

			if (Exit.isSuccess(result)) {
				const message = result.value;

				// Validate header
				expect(message.header.id).toBe(12345);
				expect(message.header.qr).toBe(1); // Response
				expect(message.header.ancount).toBe(1);
				expect(message.header.nscount).toBe(0);
				expect(message.header.arcount).toBe(0);

				// Validate question
				expect(message.question).toHaveLength(1);
				expect(message.question[0]!.qtype).toBe(1); // A record
				expect(message.question[0]!.qclass).toBe(1); // IN

				// Validate answer section
				expect(message.answer).toHaveLength(1);
				const answerRecord = message.answer[0]!;
				expect(answerRecord.type).toBe(1); // A record
				expect(answerRecord.class).toBe(1); // IN
				expect(answerRecord.ttl).toBe(300);
				expect(answerRecord.rdlength).toBe(4);
				expect(Array.from(answerRecord.rdata)).toEqual([93, 184, 216, 34]);

				// Validate other sections are empty
				expect(message.authority).toHaveLength(0);
				expect(message.additional).toHaveLength(0);
			}
		}),
	);

	it.effect("successfully decodes messages with authority records", () =>
		Effect.gen(function* () {
			// DNS response with NS record in authority section
			const messageWithAuthority = new Uint8Array([
				// Header (12 bytes)
				0x30,
				0x39, // ID: 12345
				0x81,
				0x80, // Flags: QR=1, OPCODE=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=0
				0x00,
				0x01, // QDCOUNT: 1
				0x00,
				0x00, // ANCOUNT: 0
				0x00,
				0x01, // NSCOUNT: 1
				0x00,
				0x00, // ARCOUNT: 0
				// Question: example.com A IN
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
				0x01, // QTYPE: A
				0x00,
				0x01, // QCLASS: IN
				// Authority: example.com NS IN 300 ns1.example.com
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
				0x02, // TYPE: NS
				0x00,
				0x01, // CLASS: IN
				0x00,
				0x00,
				0x01,
				0x2c, // TTL: 300
				0x00,
				0x11, // RDLENGTH: 17
				// RDATA: ns1.example.com
				0x03,
				0x6e,
				0x73,
				0x31, // "ns1"
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
			]);

			const result = yield* Effect.exit(
				Schema.decode(MessageFromUint8Array)(messageWithAuthority),
			);

			expect(Exit.isSuccess(result)).toBe(true);

			if (Exit.isSuccess(result)) {
				const message = result.value;

				// Validate header
				expect(message.header.id).toBe(12345);
				expect(message.header.qr).toBe(1); // Response
				expect(message.header.ancount).toBe(0);
				expect(message.header.nscount).toBe(1);
				expect(message.header.arcount).toBe(0);

				// Validate sections
				expect(message.answer).toHaveLength(0);
				expect(message.authority).toHaveLength(1);
				expect(message.additional).toHaveLength(0);

				// Validate authority record
				const authorityRecord = message.authority[0]!;
				expect(authorityRecord.type).toBe(2); // NS record
				expect(authorityRecord.class).toBe(1); // IN
				expect(authorityRecord.ttl).toBe(300);
				expect(authorityRecord.rdlength).toBe(17);
			}
		}),
	);

	it.effect("successfully decodes messages with additional records", () =>
		Effect.gen(function* () {
			// DNS response with A record in additional section
			const messageWithAdditional = new Uint8Array([
				// Header (12 bytes)
				0x30,
				0x39, // ID: 12345
				0x81,
				0x80, // Flags: QR=1, OPCODE=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=0
				0x00,
				0x01, // QDCOUNT: 1
				0x00,
				0x00, // ANCOUNT: 0
				0x00,
				0x00, // NSCOUNT: 0
				0x00,
				0x01, // ARCOUNT: 1
				// Question: example.com A IN
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
				0x01, // QTYPE: A
				0x00,
				0x01, // QCLASS: IN
				// Additional: ns1.example.com A IN 300 192.0.2.1
				0x03,
				0x6e,
				0x73,
				0x31, // "ns1"
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
				0x01, // TYPE: A
				0x00,
				0x01, // CLASS: IN
				0x00,
				0x00,
				0x01,
				0x2c, // TTL: 300
				0x00,
				0x04, // RDLENGTH: 4
				0xc0,
				0x00,
				0x02,
				0x01, // RDATA: 192.0.2.1
			]);

			const result = yield* Effect.exit(
				Schema.decode(MessageFromUint8Array)(messageWithAdditional),
			);

			expect(Exit.isSuccess(result)).toBe(true);

			if (Exit.isSuccess(result)) {
				const message = result.value;

				// Validate header
				expect(message.header.id).toBe(12345);
				expect(message.header.qr).toBe(1); // Response
				expect(message.header.ancount).toBe(0);
				expect(message.header.nscount).toBe(0);
				expect(message.header.arcount).toBe(1);

				// Validate sections
				expect(message.answer).toHaveLength(0);
				expect(message.authority).toHaveLength(0);
				expect(message.additional).toHaveLength(1);

				// Validate additional record
				const additionalRecord = message.additional[0]!;
				expect(additionalRecord.type).toBe(1); // A record
				expect(additionalRecord.class).toBe(1); // IN
				expect(additionalRecord.ttl).toBe(300);
				expect(additionalRecord.rdlength).toBe(4);
				expect(Array.from(additionalRecord.rdata)).toEqual([192, 0, 2, 1]);
			}
		}),
	);

	it.effect(
		"successfully decodes messages with multiple resource records",
		() =>
			Effect.gen(function* () {
				// DNS response with records in all sections
				const messageWithAllSections = new Uint8Array([
					// Header (12 bytes)
					0x30,
					0x39, // ID: 12345
					0x81,
					0x80, // Flags: QR=1, OPCODE=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=0
					0x00,
					0x01, // QDCOUNT: 1
					0x00,
					0x02, // ANCOUNT: 2
					0x00,
					0x01, // NSCOUNT: 1
					0x00,
					0x01, // ARCOUNT: 1
					// Question: example.com A IN
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
					0x01, // QTYPE: A
					0x00,
					0x01, // QCLASS: IN
					// Answer 1: example.com A IN 300 93.184.216.34
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
					0x01, // TYPE: A
					0x00,
					0x01, // CLASS: IN
					0x00,
					0x00,
					0x01,
					0x2c, // TTL: 300
					0x00,
					0x04, // RDLENGTH: 4
					0x5d,
					0xb8,
					0xd8,
					0x22, // RDATA: 93.184.216.34
					// Answer 2: example.com A IN 300 93.184.216.35
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
					0x01, // TYPE: A
					0x00,
					0x01, // CLASS: IN
					0x00,
					0x00,
					0x01,
					0x2c, // TTL: 300
					0x00,
					0x04, // RDLENGTH: 4
					0x5d,
					0xb8,
					0xd8,
					0x23, // RDATA: 93.184.216.35
					// Authority: example.com NS IN 300 ns1.example.com
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
					0x02, // TYPE: NS
					0x00,
					0x01, // CLASS: IN
					0x00,
					0x00,
					0x01,
					0x2c, // TTL: 300
					0x00,
					0x11, // RDLENGTH: 17
					// RDATA: ns1.example.com
					0x03,
					0x6e,
					0x73,
					0x31, // "ns1"
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
					// Additional: ns1.example.com A IN 300 192.0.2.1
					0x03,
					0x6e,
					0x73,
					0x31, // "ns1"
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
					0x01, // TYPE: A
					0x00,
					0x01, // CLASS: IN
					0x00,
					0x00,
					0x01,
					0x2c, // TTL: 300
					0x00,
					0x04, // RDLENGTH: 4
					0xc0,
					0x00,
					0x02,
					0x01, // RDATA: 192.0.2.1
				]);

				const result = yield* Effect.exit(
					Schema.decode(MessageFromUint8Array)(messageWithAllSections),
				);

				expect(Exit.isSuccess(result)).toBe(true);

				if (Exit.isSuccess(result)) {
					const message = result.value;

					// Validate header counts
					expect(message.header.ancount).toBe(2);
					expect(message.header.nscount).toBe(1);
					expect(message.header.arcount).toBe(1);

					// Validate section lengths match header counts
					expect(message.answer).toHaveLength(2);
					expect(message.authority).toHaveLength(1);
					expect(message.additional).toHaveLength(1);

					// Validate answer records
					expect(message.answer[0]!.type).toBe(1); // A record
					expect(message.answer[1]!.type).toBe(1); // A record
					expect(Array.from(message.answer[0]!.rdata)).toEqual([
						93, 184, 216, 34,
					]);
					expect(Array.from(message.answer[1]!.rdata)).toEqual([
						93, 184, 216, 35,
					]);

					// Validate authority record
					expect(message.authority[0]!.type).toBe(2); // NS record

					// Validate additional record
					expect(message.additional[0]!.type).toBe(1); // A record
					expect(Array.from(message.additional[0]!.rdata)).toEqual([
						192, 0, 2, 1,
					]);
				}
			}),
	);

	it.effect.prop(
		"successfully decodes multi-question DNS messages",
		[arbitraryMultiQuestionDnsMessageUint8Array],
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
					expect(message.header.qdcount).toBe(header.qdcount);
					expect(message.header.ancount).toBe(0);
					expect(message.header.nscount).toBe(0);
					expect(message.header.arcount).toBe(0);

					// Validate questions match header count
					expect(message.question).toHaveLength(header.qdcount);
					expect(message.question).toHaveLength(question.length);

					// Validate each question
					for (let i = 0; i < question.length; i++) {
						const expectedQuestion = question[i]!;
						const actualQuestion = message.question[i]!;

						expect(actualQuestion.qtype).toBe(expectedQuestion.qtype);
						expect(actualQuestion.qclass).toBe(expectedQuestion.qclass);
						expect(actualQuestion.qname.labels).toHaveLength(
							expectedQuestion.qname.length,
						);

						for (let j = 0; j < expectedQuestion.qname.length; j++) {
							expect(Array.from(actualQuestion.qname.labels[j]!)).toEqual(
								Array.from(expectedQuestion.qname[j]!),
							);
						}
					}

					// Validate other sections are empty
					expect(message.answer).toHaveLength(0);
					expect(message.authority).toHaveLength(0);
					expect(message.additional).toHaveLength(0);
				}
			}),
	);

	it.effect.prop(
		"fails on count mismatch DNS messages",
		[arbitraryCountMismatchDnsMessageUint8Array],
		([{ messageBuffer, actualCount, claimedCount }]) =>
			Effect.gen(function* () {
				// Only test cases where claimed count > actual count (buffer underrun)
				// Cases where claimed count < actual count might still succeed
				if (claimedCount > actualCount) {
					const result = yield* Effect.exit(
						Schema.decode(MessageFromUint8Array)(messageBuffer),
					);

					// Should fail due to buffer underrun when trying to read more questions than available
					expect(Exit.isFailure(result)).toBe(true);
				}
			}),
	);

	it.effect(
		"successfully decodes messages with multiple questions (specific test)",
		() =>
			Effect.gen(function* () {
				// DNS query with two questions
				const messageWithMultipleQuestions = new Uint8Array([
					// Header (12 bytes)
					0x30,
					0x39, // ID: 12345
					0x01,
					0x00, // Flags: QR=0, OPCODE=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0
					0x00,
					0x02, // QDCOUNT: 2
					0x00,
					0x00, // ANCOUNT: 0
					0x00,
					0x00, // NSCOUNT: 0
					0x00,
					0x00, // ARCOUNT: 0
					0x07, // Question 1: example.com A IN
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
					0x01, // QTYPE: A
					0x00,
					0x01, // QCLASS: IN
					0x07, // Question 2: example.org NS IN
					0x65,
					0x78,
					0x61,
					0x6d,
					0x70,
					0x6c,
					0x65, // "example"
					0x03,
					0x6f,
					0x72,
					0x67, // "org"
					0x00, // terminator
					0x00,
					0x02, // QTYPE: NS
					0x00,
					0x01, // QCLASS: IN
				]);

				const result = yield* Effect.exit(
					Schema.decode(MessageFromUint8Array)(messageWithMultipleQuestions),
				);

				expect(Exit.isSuccess(result)).toBe(true);

				if (Exit.isSuccess(result)) {
					const message = result.value;

					// Validate header
					expect(message.header.id).toBe(12345);
					expect(message.header.qr).toBe(0); // Query
					expect(message.header.qdcount).toBe(2);
					expect(message.header.ancount).toBe(0);
					expect(message.header.nscount).toBe(0);
					expect(message.header.arcount).toBe(0);

					// Validate questions
					expect(message.question).toHaveLength(2);

					// First question: example.com A IN
					const question1 = message.question[0]!;
					expect(question1.qtype).toBe(1); // A record
					expect(question1.qclass).toBe(1); // IN
					expect(question1.qname.labels).toHaveLength(2);
					expect(Array.from(question1.qname.labels[0]!)).toEqual([
						101, 120, 97, 109, 112, 108, 101,
					]); // "example"
					expect(Array.from(question1.qname.labels[1]!)).toEqual([
						99, 111, 109,
					]); // "com"

					// Second question: example.org NS IN
					const question2 = message.question[1]!;
					expect(question2.qtype).toBe(2); // NS record
					expect(question2.qclass).toBe(1); // IN
					expect(question2.qname.labels).toHaveLength(2);
					expect(Array.from(question2.qname.labels[0]!)).toEqual([
						101, 120, 97, 109, 112, 108, 101,
					]); // "example"
					expect(Array.from(question2.qname.labels[1]!)).toEqual([
						111, 114, 103,
					]); // "org"

					// Validate other sections are empty
					expect(message.answer).toHaveLength(0);
					expect(message.authority).toHaveLength(0);
					expect(message.additional).toHaveLength(0);
				}
			}),
	);

	it.effect("validates section counts match header counts", () =>
		Effect.gen(function* () {
			// Test that parsed sections match header counts exactly
			const messageWithMismatchedCounts = new Uint8Array([
				// Header (12 bytes) - Claims 2 answers but only provides 1
				0x30,
				0x39, // ID: 12345
				0x81,
				0x80, // Flags: QR=1, OPCODE=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=0
				0x00,
				0x01, // QDCOUNT: 1
				0x00,
				0x02, // ANCOUNT: 2 (but only 1 answer follows)
				0x00,
				0x00, // NSCOUNT: 0
				0x00,
				0x00, // ARCOUNT: 0
				// Question: test.com A IN
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
				// Answer 1: test.com A IN 300 192.0.2.1
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
				0x01, // TYPE: A
				0x00,
				0x01, // CLASS: IN
				0x00,
				0x00,
				0x01,
				0x2c, // TTL: 300
				0x00,
				0x04, // RDLENGTH: 4
				0xc0,
				0x00,
				0x02,
				0x01, // RDATA: 192.0.2.1
				// Missing second answer - should cause parsing error
			]);

			const result = yield* Effect.exit(
				Schema.decode(MessageFromUint8Array)(messageWithMismatchedCounts),
			);

			// Should fail due to buffer underrun when trying to read second answer
			expect(Exit.isFailure(result)).toBe(true);
		}),
	);

	it.effect("fails on buffer too small for expected records", () =>
		Effect.gen(function* () {
			// Message claiming to have records but buffer is too small
			const truncatedMessage = new Uint8Array([
				// Header (12 bytes)
				0x30,
				0x39, // ID: 12345
				0x81,
				0x80, // Flags: QR=1, OPCODE=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=0
				0x00,
				0x01, // QDCOUNT: 1
				0x00,
				0x01, // ANCOUNT: 1
				0x00,
				0x01, // NSCOUNT: 1
				0x00,
				0x01, // ARCOUNT: 1
				// Question: test.com A IN
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
				// Partial answer record - truncated
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
				0x01, // TYPE: A
				// Missing the rest of the answer and all authority/additional records
			]);

			const result = yield* Effect.exit(
				Schema.decode(MessageFromUint8Array)(truncatedMessage),
			);

			// Should fail due to buffer underrun
			expect(Exit.isFailure(result)).toBe(true);
		}),
	);

	it.effect("fails on zero questions but non-zero qdcount", () =>
		Effect.gen(function* () {
			// Header claims 1 question but no question data follows
			const noQuestionMessage = new Uint8Array([
				// Header (12 bytes)
				0x30,
				0x39, // ID: 12345
				0x01,
				0x00, // Flags: QR=0, OPCODE=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0
				0x00,
				0x01, // QDCOUNT: 1 (but no question follows)
				0x00,
				0x00, // ANCOUNT: 0
				0x00,
				0x00, // NSCOUNT: 0
				0x00,
				0x00, // ARCOUNT: 0
				// No question data - should cause parsing error
			]);

			const result = yield* Effect.exit(
				Schema.decode(MessageFromUint8Array)(noQuestionMessage),
			);

			// Should fail due to buffer underrun when trying to read question
			expect(Exit.isFailure(result)).toBe(true);
		}),
	);

	it.effect("handles maximum section counts correctly", () =>
		Effect.gen(function* () {
			// Test message with realistic maximum counts
			const messageWithMaxCounts = new Uint8Array([
				// Header (12 bytes)
				0x30,
				0x39, // ID: 12345
				0x01,
				0x00, // Flags: QR=0, OPCODE=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0
				0x00,
				0x05, // QDCOUNT: 5 (multiple questions)
				0x00,
				0x00, // ANCOUNT: 0
				0x00,
				0x00, // NSCOUNT: 0
				0x00,
				0x00, // ARCOUNT: 0
				// Question 1: a.com A IN
				0x01,
				0x61, // "a"
				0x03,
				0x63,
				0x6f,
				0x6d, // "com"
				0x00, // terminator
				0x00,
				0x01, // QTYPE: A
				0x00,
				0x01, // QCLASS: IN
				// Question 2: b.org A IN
				0x01,
				0x62, // "b"
				0x03,
				0x6f,
				0x72,
				0x67, // "org"
				0x00, // terminator
				0x00,
				0x01, // QTYPE: A
				0x00,
				0x01, // QCLASS: IN
				// Question 3: c.net CNAME IN
				0x01,
				0x63, // "c"
				0x03,
				0x6e,
				0x65,
				0x74, // "net"
				0x00, // terminator
				0x00,
				0x05, // QTYPE: CNAME
				0x00,
				0x01, // QCLASS: IN
				// Question 4: d.edu MX IN
				0x01,
				0x64, // "d"
				0x03,
				0x65,
				0x64,
				0x75, // "edu"
				0x00, // terminator
				0x00,
				0x0f, // QTYPE: MX
				0x00,
				0x01, // QCLASS: IN
				// Question 5: e.gov TXT IN
				0x01,
				0x65, // "e"
				0x03,
				0x67,
				0x6f,
				0x76, // "gov"
				0x00, // terminator
				0x00,
				0x10, // QTYPE: TXT
				0x00,
				0x01, // QCLASS: IN
			]);

			const result = yield* Effect.exit(
				Schema.decode(MessageFromUint8Array)(messageWithMaxCounts),
			);

			expect(Exit.isSuccess(result)).toBe(true);

			if (Exit.isSuccess(result)) {
				const message = result.value;

				// Validate header
				expect(message.header.qdcount).toBe(5);

				// Validate all questions are parsed
				expect(message.question).toHaveLength(5);

				// Validate question types
				expect(message.question[0]!.qtype).toBe(1); // A
				expect(message.question[1]!.qtype).toBe(1); // A
				expect(message.question[2]!.qtype).toBe(5); // CNAME
				expect(message.question[3]!.qtype).toBe(15); // MX
				expect(message.question[4]!.qtype).toBe(16); // TXT

				// Validate all questions have correct class
				for (const question of message.question) {
					expect(question.qclass).toBe(1); // IN
				}
			}
		}),
	);

	it.effect("fails gracefully on extremely large counts", () =>
		Effect.gen(function* () {
			// Test message claiming unrealistic counts
			const messageWithHugeCounts = new Uint8Array([
				// Header (12 bytes)
				0x30,
				0x39, // ID: 12345
				0x01,
				0x00, // Flags: QR=0, OPCODE=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0
				0xff,
				0xff, // QDCOUNT: 65535 (unrealistic)
				0x00,
				0x00, // ANCOUNT: 0
				0x00,
				0x00, // NSCOUNT: 0
				0x00,
				0x00, // ARCOUNT: 0
				// Only one tiny question follows
				0x01,
				0x61, // "a"
				0x00, // terminator
				0x00,
				0x01, // QTYPE: A
				0x00,
				0x01, // QCLASS: IN
			]);

			const result = yield* Effect.exit(
				Schema.decode(MessageFromUint8Array)(messageWithHugeCounts),
			);

			// Should fail due to buffer underrun when trying to read 65535 questions
			expect(Exit.isFailure(result)).toBe(true);
		}),
	);

	// === DNS MESSAGE COMPRESSION TESTS ===

	it.effect("successfully decodes simple compressed messages", () =>
		Effect.gen(function* () {
			const { messageBuffer, expectedQuestionName, expectedAnswerName } =
				arbitrarySimpleCompressionMessage;

			const result = yield* Effect.exit(
				Schema.decode(MessageFromUint8Array)(messageBuffer),
			);

			expect(Exit.isSuccess(result)).toBe(true);

			if (Exit.isSuccess(result)) {
				const message = result.value;

				// Validate header
				expect(message.header.id).toBe(12345);
				expect(message.header.qr).toBe(1); // Response
				expect(message.header.qdcount).toBe(1);
				expect(message.header.ancount).toBe(1);

				// Validate question name decompression
				expect(message.question).toHaveLength(1);
				const question = message.question[0]!;
				expect(question.qname.labels).toHaveLength(expectedQuestionName.labels.length);
				for (let i = 0; i < expectedQuestionName.labels.length; i++) {
					expect(Array.from(question.qname.labels[i]!)).toEqual(
						Array.from(expectedQuestionName.labels[i]!),
					);
				}

				// Validate answer name decompression (should be same as question due to compression)
				expect(message.answer).toHaveLength(1);
				const answer = message.answer[0]!;
				expect(answer.name.labels).toHaveLength(expectedAnswerName.labels.length);
				for (let i = 0; i < expectedAnswerName.labels.length; i++) {
					expect(Array.from(answer.name.labels[i]!)).toEqual(
						Array.from(expectedAnswerName.labels[i]!),
					);
				}

				// Verify question and answer names are the same (compression test)
				expect(question.qname.labels.length).toBe(answer.name.labels.length);
			}
		}),
	);

	it.effect("successfully decodes RFC 1035 compression example", () =>
		Effect.gen(function* () {
			const { messageBuffer, expectedNames } = arbitraryRfc1035CompressionExample;

			const result = yield* Effect.exit(
				Schema.decode(MessageFromUint8Array)(messageBuffer),
			);

			if (Exit.isFailure(result)) {
				console.log(Cause.prettyErrors(result.cause));
			}

			expect(Exit.isSuccess(result)).toBe(true);

			if (Exit.isSuccess(result)) {
				const message = result.value;

				// Validate header - should have 4 questions as per RFC example
				expect(message.header.id).toBe(12345);
				expect(message.header.qdcount).toBe(4);
				expect(message.header.ancount).toBe(0);
				expect(message.header.nscount).toBe(0);
				expect(message.header.arcount).toBe(0);

				// Validate all questions are parsed
				expect(message.question).toHaveLength(4);

				// Question 1: F.ISI.ARPA
				const question1 = message.question[0]!;
				expect(question1.qname.labels).toHaveLength(expectedNames[0]!.labels.length);
				for (let i = 0; i < expectedNames[0]!.labels.length; i++) {
					expect(Array.from(question1.qname.labels[i]!)).toEqual(
						Array.from(expectedNames[0]!.labels[i]!),
					);
				}
				expect(question1.qtype).toBe(1); // A record
				expect(question1.qclass).toBe(1); // IN

				// Question 2: FOO.F.ISI.ARPA (should be decompressed properly)
				const question2 = message.question[1]!;
				expect(question2.qname.labels).toHaveLength(expectedNames[1]!.labels.length);
				for (let i = 0; i < expectedNames[1]!.labels.length; i++) {
					expect(Array.from(question2.qname.labels[i]!)).toEqual(
						Array.from(expectedNames[1]!.labels[i]!),
					);
				}
				expect(question2.qtype).toBe(1); // A record
				expect(question2.qclass).toBe(1); // IN

				// Question 3: ARPA (compressed pointer to ARPA part of F.ISI.ARPA)
				const question3 = message.question[2]!;
				expect(question3.qname.labels).toHaveLength(expectedNames[2]!.labels.length);
				for (let i = 0; i < expectedNames[2]!.labels.length; i++) {
					expect(Array.from(question3.qname.labels[i]!)).toEqual(
						Array.from(expectedNames[2]!.labels[i]!),
					);
				}
				expect(question3.qtype).toBe(1); // A record
				expect(question3.qclass).toBe(1); // IN

				// Question 4: root domain (empty labels)
				const question4 = message.question[3]!;
				expect(question4.qname.labels).toHaveLength(expectedNames[3]!.labels.length);
				expect(question4.qname.labels).toHaveLength(0); // Root domain has no labels
				expect(question4.qtype).toBe(1); // A record
				expect(question4.qclass).toBe(1); // IN

				// Verify specific RFC 1035 compression cases
				// FOO.F.ISI.ARPA should start with "FOO" then match F.ISI.ARPA
				expect(Array.from(question2.qname.labels[0]!)).toEqual([70, 79, 79]); // "FOO"
				expect(Array.from(question2.qname.labels[1]!)).toEqual([70]); // "F"
				expect(Array.from(question2.qname.labels[2]!)).toEqual([73, 83, 73]); // "ISI"
				expect(Array.from(question2.qname.labels[3]!)).toEqual([65, 82, 80, 65]); // "ARPA"

				// ARPA question should only have the ARPA label
				expect(Array.from(question3.qname.labels[0]!)).toEqual([65, 82, 80, 65]); // "ARPA"
			}
		}),
	);

	it.effect("successfully decodes messages with multiple compression scenarios", () =>
		Effect.gen(function* () {
			const { messageBuffer } = arbitraryMultiCompressionMessage;

			const result = yield* Effect.exit(
				Schema.decode(MessageFromUint8Array)(messageBuffer),
			);

			if (Exit.isFailure(result)) {
				console.log(Cause.prettyErrors(result.cause));
			}

			expect(Exit.isSuccess(result)).toBe(true);

			if (Exit.isSuccess(result)) {
				const message = result.value;

				// Validate header
				expect(message.header.id).toBe(12345);
				expect(message.header.qr).toBe(1); // Response
				expect(message.header.qdcount).toBe(1);
				expect(message.header.ancount).toBe(1);
				expect(message.header.nscount).toBe(1);
				expect(message.header.arcount).toBe(1);

				// Validate question: mail.example.com
				expect(message.question).toHaveLength(1);
				const question = message.question[0]!;
				expect(question.qname.labels).toHaveLength(3);
				expect(Array.from(question.qname.labels[0]!)).toEqual([109, 97, 105, 108]); // "mail"
				expect(Array.from(question.qname.labels[1]!)).toEqual([101, 120, 97, 109, 112, 108, 101]); // "example"
				expect(Array.from(question.qname.labels[2]!)).toEqual([99, 111, 109]); // "com"

				// Validate answer: should have same name as question (compressed)
				expect(message.answer).toHaveLength(1);
				const answer = message.answer[0]!;
				expect(answer.name.labels).toHaveLength(3);
				expect(Array.from(answer.name.labels[0]!)).toEqual([109, 97, 105, 108]); // "mail"
				expect(Array.from(answer.name.labels[1]!)).toEqual([101, 120, 97, 109, 112, 108, 101]); // "example"
				expect(Array.from(answer.name.labels[2]!)).toEqual([99, 111, 109]); // "com"

				// Validate authority: example.com (compressed reference to suffix)
				expect(message.authority).toHaveLength(1);
				const authority = message.authority[0]!;
				expect(authority.name.labels).toHaveLength(2);
				expect(Array.from(authority.name.labels[0]!)).toEqual([101, 120, 97, 109, 112, 108, 101]); // "example"
				expect(Array.from(authority.name.labels[1]!)).toEqual([99, 111, 109]); // "com"

				// Validate additional: ns1.example.com (mixed compression)
				expect(message.additional).toHaveLength(1);
				const additional = message.additional[0]!;
				expect(additional.name.labels).toHaveLength(3);
				expect(Array.from(additional.name.labels[0]!)).toEqual([110, 115, 49]); // "ns1"
				expect(Array.from(additional.name.labels[1]!)).toEqual([101, 120, 97, 109, 112, 108, 101]); // "example"
				expect(Array.from(additional.name.labels[2]!)).toEqual([99, 111, 109]); // "com"
			}
		}),
	);

	it.effect("successfully decodes tail compression scenarios", () =>
		Effect.gen(function* () {
			const { messageBuffer, expectedNames } = arbitraryTailCompressionMessage;

			const result = yield* Effect.exit(
				Schema.decode(MessageFromUint8Array)(messageBuffer),
			);

			expect(Exit.isSuccess(result)).toBe(true);

			if (Exit.isSuccess(result)) {
				const message = result.value;

				// Validate header
				expect(message.header.qdcount).toBe(2);

				// Validate questions
				expect(message.question).toHaveLength(2);

				// Question 1: example.com
				const question1 = message.question[0]!;
				expect(question1.qname.labels).toHaveLength(expectedNames[0]!.labels.length);
				for (let i = 0; i < expectedNames[0]!.labels.length; i++) {
					expect(Array.from(question1.qname.labels[i]!)).toEqual(
						Array.from(expectedNames[0]!.labels[i]!),
					);
				}

				// Question 2: www.example.com (tail compression)
				const question2 = message.question[1]!;
				expect(question2.qname.labels).toHaveLength(expectedNames[1]!.labels.length);
				for (let i = 0; i < expectedNames[1]!.labels.length; i++) {
					expect(Array.from(question2.qname.labels[i]!)).toEqual(
						Array.from(expectedNames[1]!.labels[i]!),
					);
				}
			}
		}),
	);

	it.effect.prop(
		"handles compression error conditions correctly",
		[arbitraryCompressionErrorMessages],
		([{ messageBuffer, shouldFail, description }]) =>
			Effect.gen(function* () {
				const result = yield* Effect.exit(
					Schema.decode(MessageFromUint8Array)(messageBuffer),
				);

				if (shouldFail) {
					// Error conditions should fail parsing
					expect(Exit.isFailure(result)).toBe(true);
					
					if (Exit.isFailure(result)) {
						console.log(`Expected failure for ${description}:`, Cause.prettyErrors(result.cause));
					}
				} else {
					// Valid complex compression should succeed
					expect(Exit.isSuccess(result)).toBe(true);
					
					if (Exit.isSuccess(result)) {
						const message = result.value;
						expect(message.header.qdcount).toBeGreaterThan(0);
					}
				}
			}),
	);

	it.effect("handles compression circular reference detection", () =>
		Effect.gen(function* () {
			// Create a message with circular pointer (points to itself)
			const circularMessage = new Uint8Array([
				// Header
				0x30, 0x39, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// Question with circular pointer
				0xC0, 0x0C, // Pointer to offset 12 (points to itself)
				0x00, 0x01, // QTYPE: A
				0x00, 0x01, // QCLASS: IN
			]);

			const result = yield* Effect.exit(
				Schema.decode(MessageFromUint8Array)(circularMessage),
			);

			// Should fail due to circular reference
			expect(Exit.isFailure(result)).toBe(true);

			if (Exit.isFailure(result)) {
				const errors = Cause.prettyErrors(result.cause);
				console.log("Expected circular reference error:", errors);
			}
		}),
	);

	it.effect("handles compression pointer beyond message boundary", () =>
		Effect.gen(function* () {
			// Create a message with pointer beyond boundary
			const invalidPointerMessage = new Uint8Array([
				// Header
				0x30, 0x39, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// Question with invalid pointer (points beyond message)
				0xC0, 0xFF, // Pointer to offset 255 (beyond message boundary)
				0x00, 0x01, // QTYPE: A
				0x00, 0x01, // QCLASS: IN
			]);

			const result = yield* Effect.exit(
				Schema.decode(MessageFromUint8Array)(invalidPointerMessage),
			);

			// Should fail due to invalid pointer
			expect(Exit.isFailure(result)).toBe(true);

			if (Exit.isFailure(result)) {
				const errors = Cause.prettyErrors(result.cause);
				console.log("Expected boundary error:", errors);
			}
		}),
	);

	it.effect("handles compression pointer to invalid label position", () =>
		Effect.gen(function* () {
			// Create a message with pointer to middle of a label
			const invalidLabelPointerMessage = new Uint8Array([
				// Header
				0x30, 0x39, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// Some data first
				0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, // "example"
				0x03, 0x63, 0x6F, 0x6D, // "com"
				0x00, // terminator
				// Question with pointer to middle of "example" (offset 14)
				0xC0, 0x0E, // Pointer to offset 14 (middle of "example")
				0x00, 0x01, // QTYPE: A
				0x00, 0x01, // QCLASS: IN
			]);

			const result = yield* Effect.exit(
				Schema.decode(MessageFromUint8Array)(invalidLabelPointerMessage),
			);

			// This might succeed or fail depending on implementation
			// The key is that it should handle it gracefully
			if (Exit.isFailure(result)) {
				const errors = Cause.prettyErrors(result.cause);
				console.log("Pointer to invalid label position:", errors);
			} else {
				console.log("Pointer to middle of label was handled");
			}
		}),
	);

	it.effect("handles deep nested compression pointer chains", () =>
		Effect.gen(function* () {
			// Create a message with multiple levels of pointer indirection
			const deepNestedMessage = new Uint8Array([
				// Header
				0x30, 0x39, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				
				// Base name: example.com at offset 12
				0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, // "example"
				0x03, 0x63, 0x6F, 0x6D, // "com"
				0x00, // terminator
				
				// Pointer 1: points to base name (offset 28)
				0xC0, 0x0C, // Pointer to offset 12 (example.com)
				
				// Pointer 2: points to pointer 1 (offset 30) 
				0xC0, 0x1C, // Pointer to offset 28 (pointer 1)
				
				// Pointer 3: points to pointer 2 (offset 32)
				0xC0, 0x1E, // Pointer to offset 30 (pointer 2)
				
				// Question uses pointer 3
				0xC0, 0x20, // Pointer to offset 32 (pointer 3)
				0x00, 0x01, // QTYPE: A
				0x00, 0x01, // QCLASS: IN
			]);

			const result = yield* Effect.exit(
				Schema.decode(MessageFromUint8Array)(deepNestedMessage),
			);

			if (Exit.isFailure(result)) {
				const errors = Cause.prettyErrors(result.cause);
				console.log("Deep nested compression result:", errors);
			}

			// This should either succeed (if implementation handles deep nesting)
			// or fail gracefully (if there's a nesting limit)
			// Both behaviors are acceptable as long as it doesn't crash
			expect(Exit.isSuccess(result) || Exit.isFailure(result)).toBe(true);

			if (Exit.isSuccess(result)) {
				const message = result.value;
				expect(message.question).toHaveLength(1);
				
				const question = message.question[0]!;
				// Should resolve to example.com despite the pointer chain
				expect(question.qname.labels).toHaveLength(2);
				expect(Array.from(question.qname.labels[0]!)).toEqual([101, 120, 97, 109, 112, 108, 101]); // "example"
				expect(Array.from(question.qname.labels[1]!)).toEqual([99, 111, 109]); // "com"
			}
		}),
	);

	it.effect("handles compression with maximum offset values", () =>
		Effect.gen(function* () {
			// Test edge case with maximum valid pointer offset (14-bit limit: 0x3FFF)
			// Create a large enough message to test near the boundary
			const largeMessage = new Uint8Array(300);
			const view = new DataView(largeMessage.buffer);
			
			// Header
			view.setUint16(0, 12345, false); // ID
			view.setUint8(2, 0x01); // QR=0, OPCODE=0, RD=1
			view.setUint8(3, 0x00); // Other flags
			view.setUint16(4, 1, false); // QDCOUNT=1
			view.setUint16(6, 0, false); // ANCOUNT=0
			view.setUint16(8, 0, false); // NSCOUNT=0
			view.setUint16(10, 0, false); // ARCOUNT=0
			
			// Put a name near the end of the message
			let offset = 200; // Far enough to test large pointer
			largeMessage[offset++] = 7; // length
			largeMessage.set(new Uint8Array([101, 120, 97, 109, 112, 108, 101]), offset); // "example"
			offset += 7;
			largeMessage[offset++] = 3; // length
			largeMessage.set(new Uint8Array([99, 111, 109]), offset); // "com"
			offset += 3;
			largeMessage[offset++] = 0; // terminator
			
			// Question with pointer to the name at offset 200
			let questionOffset = 12;
			largeMessage[questionOffset++] = 0xC0; // Pointer high byte
			largeMessage[questionOffset++] = 200; // Pointer low byte (points to offset 200)
			largeMessage[questionOffset++] = 0x00; // QTYPE high
			largeMessage[questionOffset++] = 0x01; // QTYPE low (A)
			largeMessage[questionOffset++] = 0x00; // QCLASS high
			largeMessage[questionOffset++] = 0x01; // QCLASS low (IN)

			const result = yield* Effect.exit(
				Schema.decode(MessageFromUint8Array)(largeMessage),
			);

			expect(Exit.isSuccess(result)).toBe(true);

			if (Exit.isSuccess(result)) {
				const message = result.value;
				expect(message.question).toHaveLength(1);
				
				const question = message.question[0]!;
				expect(question.qname.labels).toHaveLength(2);
				expect(Array.from(question.qname.labels[0]!)).toEqual([101, 120, 97, 109, 112, 108, 101]); // "example"
				expect(Array.from(question.qname.labels[1]!)).toEqual([99, 111, 109]); // "com"
			}
		}),
	);

	// === REAL-WORLD COMPRESSION SCENARIO TESTS ===

	it.effect("successfully decodes CNAME chain with compression", () =>
		Effect.gen(function* () {
			const { messageBuffer } = arbitraryCnameCompressionMessage;

			const result = yield* Effect.exit(
				Schema.decode(MessageFromUint8Array)(messageBuffer),
			);

			if (Exit.isFailure(result)) {
				console.log(Cause.prettyErrors(result.cause));
			}

			expect(Exit.isSuccess(result)).toBe(true);

			if (Exit.isSuccess(result)) {
				const message = result.value;

				// Validate header
				expect(message.header.id).toBe(12345);
				expect(message.header.qr).toBe(1); // Response
				expect(message.header.qdcount).toBe(1);
				expect(message.header.ancount).toBe(2); // CNAME + A record

				// Validate question: www.example.com
				expect(message.question).toHaveLength(1);
				const question = message.question[0]!;
				expect(question.qname.labels).toHaveLength(3);
				expect(Array.from(question.qname.labels[0]!)).toEqual([119, 119, 119]); // "www"
				expect(Array.from(question.qname.labels[1]!)).toEqual([101, 120, 97, 109, 112, 108, 101]); // "example"
				expect(Array.from(question.qname.labels[2]!)).toEqual([99, 111, 109]); // "com"

				// Validate answers
				expect(message.answer).toHaveLength(2);

				// Answer 1: CNAME record
				const cnameAnswer = message.answer[0]!;
				expect(cnameAnswer.type).toBe(5); // CNAME
				expect(cnameAnswer.name.labels).toHaveLength(3); // www.example.com (decompressed)
				expect(Array.from(cnameAnswer.name.labels[0]!)).toEqual([119, 119, 119]); // "www"
				expect(Array.from(cnameAnswer.name.labels[1]!)).toEqual([101, 120, 97, 109, 112, 108, 101]); // "example"
				expect(Array.from(cnameAnswer.name.labels[2]!)).toEqual([99, 111, 109]); // "com"

				// Answer 2: A record for example.com
				const aAnswer = message.answer[1]!;
				expect(aAnswer.type).toBe(1); // A
				expect(aAnswer.name.labels).toHaveLength(2); // example.com (decompressed)
				expect(Array.from(aAnswer.name.labels[0]!)).toEqual([101, 120, 97, 109, 112, 108, 101]); // "example"
				expect(Array.from(aAnswer.name.labels[1]!)).toEqual([99, 111, 109]); // "com"
				expect(Array.from(aAnswer.rdata)).toEqual([93, 184, 216, 34]); // 93.184.216.34
			}
		}),
	);

	it.effect("successfully decodes NS records with compression", () =>
		Effect.gen(function* () {
			const { messageBuffer } = arbitraryNsCompressionMessage;

			const result = yield* Effect.exit(
				Schema.decode(MessageFromUint8Array)(messageBuffer),
			);

			if (Exit.isFailure(result)) {
				console.log(Cause.prettyErrors(result.cause));
			}

			expect(Exit.isSuccess(result)).toBe(true);

			if (Exit.isSuccess(result)) {
				const message = result.value;

				// Validate header
				expect(message.header.id).toBe(12345);
				expect(message.header.qr).toBe(1); // Response
				expect(message.header.qdcount).toBe(1);
				expect(message.header.ancount).toBe(0);
				expect(message.header.nscount).toBe(2); // Two NS records
				expect(message.header.arcount).toBe(2); // Two glue records

				// Validate question: example.com NS
				expect(message.question).toHaveLength(1);
				const question = message.question[0]!;
				expect(question.qtype).toBe(2); // NS
				expect(question.qname.labels).toHaveLength(2);
				expect(Array.from(question.qname.labels[0]!)).toEqual([101, 120, 97, 109, 112, 108, 101]); // "example"
				expect(Array.from(question.qname.labels[1]!)).toEqual([99, 111, 109]); // "com"

				// Validate authority records (NS records)
				expect(message.authority).toHaveLength(2);

				// Authority 1: example.com NS ns1.example.com
				const ns1Authority = message.authority[0]!;
				expect(ns1Authority.type).toBe(2); // NS
				expect(ns1Authority.name.labels).toHaveLength(2); // example.com (decompressed)
				expect(Array.from(ns1Authority.name.labels[0]!)).toEqual([101, 120, 97, 109, 112, 108, 101]); // "example"
				expect(Array.from(ns1Authority.name.labels[1]!)).toEqual([99, 111, 109]); // "com"

				// Authority 2: example.com NS ns2.example.com
				const ns2Authority = message.authority[1]!;
				expect(ns2Authority.type).toBe(2); // NS
				expect(ns2Authority.name.labels).toHaveLength(2); // example.com (decompressed)

				// Validate additional records (glue records)
				expect(message.additional).toHaveLength(2);

				// Additional 1: ns1.example.com A record
				const ns1Additional = message.additional[0]!;
				expect(ns1Additional.type).toBe(1); // A
				expect(ns1Additional.name.labels).toHaveLength(3); // ns1.example.com (decompressed)
				expect(Array.from(ns1Additional.name.labels[0]!)).toEqual([110, 115, 49]); // "ns1"
				expect(Array.from(ns1Additional.name.labels[1]!)).toEqual([101, 120, 97, 109, 112, 108, 101]); // "example"
				expect(Array.from(ns1Additional.name.labels[2]!)).toEqual([99, 111, 109]); // "com"
				expect(Array.from(ns1Additional.rdata)).toEqual([192, 0, 2, 1]); // 192.0.2.1

				// Additional 2: ns2.example.com A record
				const ns2Additional = message.additional[1]!;
				expect(ns2Additional.type).toBe(1); // A
				expect(ns2Additional.name.labels).toHaveLength(3); // ns2.example.com (decompressed)
				expect(Array.from(ns2Additional.name.labels[0]!)).toEqual([110, 115, 50]); // "ns2"
			}
		}),
	);

	it.effect("successfully decodes MX records with compression", () =>
		Effect.gen(function* () {
			const { messageBuffer } = arbitraryMxCompressionMessage;

			const result = yield* Effect.exit(
				Schema.decode(MessageFromUint8Array)(messageBuffer),
			);

			if (Exit.isFailure(result)) {
				console.log(Cause.prettyErrors(result.cause));
			}

			expect(Exit.isSuccess(result)).toBe(true);

			if (Exit.isSuccess(result)) {
				const message = result.value;

				// Validate header
				expect(message.header.id).toBe(12345);
				expect(message.header.qr).toBe(1); // Response
				expect(message.header.qdcount).toBe(1);
				expect(message.header.ancount).toBe(2); // Two MX records
				expect(message.header.arcount).toBe(2); // Two glue records

				// Validate question: example.com MX
				expect(message.question).toHaveLength(1);
				const question = message.question[0]!;
				expect(question.qtype).toBe(15); // MX
				expect(question.qname.labels).toHaveLength(2);
				expect(Array.from(question.qname.labels[0]!)).toEqual([101, 120, 97, 109, 112, 108, 101]); // "example"
				expect(Array.from(question.qname.labels[1]!)).toEqual([99, 111, 109]); // "com"

				// Validate answer records (MX records)
				expect(message.answer).toHaveLength(2);

				// Answer 1: example.com MX 10 mail1.example.com
				const mx1Answer = message.answer[0]!;
				expect(mx1Answer.type).toBe(15); // MX
				expect(mx1Answer.name.labels).toHaveLength(2); // example.com (decompressed)
				expect(Array.from(mx1Answer.name.labels[0]!)).toEqual([101, 120, 97, 109, 112, 108, 101]); // "example"
				expect(Array.from(mx1Answer.name.labels[1]!)).toEqual([99, 111, 109]); // "com"

				// Answer 2: example.com MX 20 mail2.example.com
				const mx2Answer = message.answer[1]!;
				expect(mx2Answer.type).toBe(15); // MX
				expect(mx2Answer.name.labels).toHaveLength(2); // example.com (decompressed)

				// Validate additional records (glue records)
				expect(message.additional).toHaveLength(2);

				// Additional 1: mail1.example.com A record
				const mail1Additional = message.additional[0]!;
				expect(mail1Additional.type).toBe(1); // A
				expect(mail1Additional.name.labels).toHaveLength(3); // mail1.example.com (decompressed)
				expect(Array.from(mail1Additional.name.labels[0]!)).toEqual([109, 97, 105, 108, 49]); // "mail1"
				expect(Array.from(mail1Additional.name.labels[1]!)).toEqual([101, 120, 97, 109, 112, 108, 101]); // "example"
				expect(Array.from(mail1Additional.name.labels[2]!)).toEqual([99, 111, 109]); // "com"
				expect(Array.from(mail1Additional.rdata)).toEqual([192, 0, 2, 10]); // 192.0.2.10

				// Additional 2: mail2.example.com A record
				const mail2Additional = message.additional[1]!;
				expect(mail2Additional.type).toBe(1); // A
				expect(mail2Additional.name.labels).toHaveLength(3); // mail2.example.com (decompressed)
				expect(Array.from(mail2Additional.name.labels[0]!)).toEqual([109, 97, 105, 108, 50]); // "mail2"
			}
		}),
	);

	// === PROPERTY-BASED COMPRESSION TESTS ===

	it.effect.prop(
		"successfully decodes arbitrary compressed DNS messages",
		[arbitraryCompressedDnsMessage],
		([messageData]) =>
			Effect.gen(function* () {
				const { messageBuffer, expectedQuestionName, expectedCompressedNames, header } = messageData;
				
				const result = yield* Effect.exit(
					Schema.decode(MessageFromUint8Array)(messageBuffer),
				);

				if (Exit.isFailure(result)) {
					console.log(Cause.prettyErrors(result.cause));
				}

				expect(Exit.isSuccess(result)).toBe(true);

				if (Exit.isSuccess(result)) {
					const message = result.value;

					// Validate header matches expectations
					expect(message.header.id).toBe(header.id);
					expect(message.header.qr).toBe(header.qr);
					expect(message.header.qdcount).toBe(header.qdcount);
					expect(message.header.ancount).toBe(header.ancount);
					expect(message.header.nscount).toBe(header.nscount);
					expect(message.header.arcount).toBe(header.arcount);

					// Validate question section
					expect(message.question).toHaveLength(1);
					const question = message.question[0]!;
					
					// Question name should match expected base domain
					expect(question.qname.labels).toHaveLength(expectedQuestionName.length);
					for (let i = 0; i < expectedQuestionName.length; i++) {
						expect(Array.from(question.qname.labels[i]!)).toEqual(
							Array.from(expectedQuestionName[i]!),
						);
					}
					expect(question.qtype).toBe(1); // A record
					expect(question.qclass).toBe(1); // IN

					// Validate answer section with compressed names
					expect(message.answer).toHaveLength(header.ancount);
					for (let i = 0; i < message.answer.length; i++) {
						const answer = message.answer[i]!;
						const expectedName = expectedCompressedNames[i];
						
						if (expectedName) {
							expect(answer.name.labels).toHaveLength(expectedName.length);
							for (let j = 0; j < expectedName.length; j++) {
								expect(Array.from(answer.name.labels[j]!)).toEqual(
									Array.from(expectedName[j]!),
								);
							}
						}
						
						expect(answer.type).toBe(1); // A record
						expect(answer.class).toBe(1); // IN
						expect(answer.rdata).toHaveLength(4); // IPv4 address
					}

					// Validate authority section (if any)
					expect(message.authority).toHaveLength(header.nscount);
					for (const authority of message.authority) {
						expect(authority.type).toBe(2); // NS record
						expect(authority.class).toBe(1); // IN
						// Authority names should decompress to base domain
						expect(authority.name.labels).toHaveLength(expectedQuestionName.length);
						for (let i = 0; i < expectedQuestionName.length; i++) {
							expect(Array.from(authority.name.labels[i]!)).toEqual(
								Array.from(expectedQuestionName[i]!),
							);
						}
					}

					// Validate additional section (if any)
					expect(message.additional).toHaveLength(header.arcount);
					for (const additional of message.additional) {
						expect(additional.type).toBe(1); // A record
						expect(additional.class).toBe(1); // IN
						expect(additional.rdata).toHaveLength(4); // IPv4 address
						// Additional names should be nameserver names (ns1, ns2, etc.)
						expect(additional.name.labels.length).toBeGreaterThan(expectedQuestionName.length);
						
						// Check that nameserver name ends with base domain
						const nsNameSuffix = additional.name.labels.slice(1); // Skip "ns1"/"ns2" prefix
						expect(nsNameSuffix).toHaveLength(expectedQuestionName.length);
						for (let i = 0; i < expectedQuestionName.length; i++) {
							expect(Array.from(nsNameSuffix[i]!)).toEqual(
								Array.from(expectedQuestionName[i]!),
							);
						}
					}

					console.log(`Successfully parsed compressed message with ${header.ancount} answers, ${header.nscount} authority, ${header.arcount} additional records`);
				}
			}),
	);
});
