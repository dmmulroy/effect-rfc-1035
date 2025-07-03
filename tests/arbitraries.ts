import { FastCheck as fc } from "effect";
import { RRTypeNameToRRType } from "../src";

// RFC-compliant DNS label generator (letters, digits, hyphens only)
// RFC 1035: Must start and end with letter/digit, no consecutive hyphens
export const arbitraryValidDnsLabel = fc
	.stringMatching(/^[a-zA-Z0-9]([a-zA-Z0-9]|[a-zA-Z0-9]-[a-zA-Z0-9])*$/)
	.filter((s) => s.length >= 1 && s.length <= 63)
	.filter((s) => !s.includes("--")) // No consecutive hyphens
	.map((s) => new Uint8Array(Array.from(s, (c) => c.charCodeAt(0))));

// Generate realistic domain names with proper DNS structure
export const arbitraryValidDomainName = fc
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

export const arbitraryValidQuestionDnsHeader = fc.record({
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

export const arbitraryValidAnswerDnsHeader = fc.record({
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
export const arbitraryValidDnsHeader = fc.oneof(
	arbitraryValidQuestionDnsHeader,
	arbitraryValidAnswerDnsHeader,
);

// Generate headers with RFC violations for negative testing
export const arbitraryInvalidDnsHeader = fc.record({
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
export const arbitraryValidDnsHeaderUint8Array = arbitraryValidDnsHeader.map(
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
export const arbitraryInvalidDnsHeaderUint8Array =
	arbitraryInvalidDnsHeader.map((header) => {
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
	});

// Generate valid DNS question
export const arbitraryValidDnsQuestion = fc.record({
	qname: arbitraryValidDomainName,
	qtype: fc.constantFrom(...Object.values(RRTypeNameToRRType)),
	qclass: fc.constantFrom(1, 3, 4), // IN, CH, HS
});

// Generate valid DNS question as Uint8Array
export const arbitraryValidDnsQuestionUint8Array =
	arbitraryValidDnsQuestion.map((question) => {
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
	});

// Generate realistic TTL values
export const arbitraryRealisticTtl = fc.oneof(
	fc.constantFrom(0, 60, 300, 3600, 86400), // Common values
	fc.integer({ min: 1, max: 2147483647 }), // Valid 31-bit range
);

// Generate valid resource record
export const arbitraryValidResourceRecord = fc
	.record({
		name: arbitraryValidDomainName,
		type: fc.constantFrom(...Object.values(RRTypeNameToRRType)),
		class: fc.constantFrom(1, 3, 4),
		ttl: arbitraryRealisticTtl,
		rdlength: fc.integer({ min: 0, max: 512 }),
	})
	.filter((record) => {
		// A records must have 4 byte rdlength
		if (record.type === 1 && record.rdlength !== 4) {
			return false;
		}
		return true;
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
export const arbitraryValidResourceRecordUint8Array =
	arbitraryValidResourceRecord.map((record) => {
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
	});

// Generate valid Label instances (Uint8Array with valid characters)
// RFC-1035: Labels can contain letters, digits, and hyphens
// Must start and end with letter or digit, no consecutive hyphens
export const arbitraryValidLabel = fc.oneof(
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

export const arbitraryInvalidLabel = fc.oneof(
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

	// Consecutive hyphens in the 3rd and 4th indices
	fc
		.tuple(fc.string({ unit: charFrom(ALPHA_NUM), maxLength: 30 }))
		.map(([value]) => encode(`AA--${value}`)),
);

// Generate valid Name instances (arrays of valid Labels)
// RFC 1035: Names must be 255 octets or less total
export const arbitraryValidName = fc
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
export const arbitraryInvalidName = fc.oneof(
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
export const arbitraryValidNameUint8Array = arbitraryValidName.map((name) => {
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
export const arbitraryInvalidNameUint8Array = fc.oneof(
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

// Generate valid Name struct instances from wire format
// This ensures the encodedByteLength property is properly set
export const arbitraryValidNameStruct = arbitraryValidNameUint8Array.map(
	(wireFormat) => {
		// Parse the wire format to extract labels and calculate encoded byte length
		const labels: Uint8Array[] = [];
		let offset = 0;

		while (offset < wireFormat.length) {
			const length = wireFormat[offset] ?? 0;
			if (length === 0) {
				offset++; // Skip terminator
				break;
			}

			const label = wireFormat.subarray(offset + 1, offset + 1 + length);
			labels.push(label);
			offset += length + 1;
		}

		// Create expected Name struct with correct encodedByteLength
		// The encodedByteLength should equal the total wire format length
		const expectedName = {
			labels,
			encodedByteLength: wireFormat.length,
		};
		return { wireFormat, expectedName };
	},
);

// Generate invalid Name wire format test cases
export const arbitraryInvalidNameWireFormat = fc.oneof(
	// Wire format that's too short
	fc.constant(new Uint8Array([1])), // Length byte without data

	// Wire format missing terminator
	fc.constant(new Uint8Array([3, 65, 66, 67])), // "ABC" without null terminator

	// Wire format with oversized label
	fc.constant(new Uint8Array([64, ...new Array(64).fill(65), 0])), // 64-byte label (invalid)

	// Wire format that would exceed 255 total bytes
	fc.constant(new Uint8Array(300).fill(1)), // Invalid structure, too large
);

// Generate valid DNS message (header + question only, since answer/authority/additional are not implemented)
export const arbitraryValidDnsMessage = fc
	.record({
		header: arbitraryValidQuestionDnsHeader,
		question: arbitraryValidDnsQuestion,
	})
	.chain(({ header, question }) => {
		// Ensure header.qdcount is 1 for single question
		const updatedHeader = {
			...header,
			qdcount: 1,
			ancount: 0,
			nscount: 0,
			arcount: 0,
		};
		return fc.constant({ header: updatedHeader, question: [question] });
	});

// Generate valid DNS message with multiple questions
export const arbitraryMultiQuestionDnsMessage = fc
	.record({
		header: arbitraryValidQuestionDnsHeader,
		questionCount: fc.integer({ min: 2, max: 5 }),
	})
	.chain(({ header, questionCount }) => {
		// Generate multiple questions
		return fc.array(arbitraryValidDnsQuestion, { 
			minLength: questionCount, 
			maxLength: questionCount 
		}).map(questions => {
			const updatedHeader = {
				...header,
				qdcount: questionCount,
				ancount: 0,
				nscount: 0,
				arcount: 0,
			};
			return { header: updatedHeader, question: questions };
		});
	});

// Generate valid DNS message as Uint8Array
export const arbitraryValidDnsMessageUint8Array = arbitraryValidDnsMessage.map(
	(message) => {
		// Generate header bytes
		const headerBuffer = new ArrayBuffer(12);
		const headerView = new DataView(headerBuffer);

		headerView.setUint16(0, message.header.id, false);

		let byte2 = 0;
		byte2 |= (message.header.qr & 0x01) << 7;
		byte2 |= (message.header.opcode & 0x0f) << 3;
		byte2 |= (message.header.aa & 0x01) << 2;
		byte2 |= (message.header.tc & 0x01) << 1;
		byte2 |= message.header.rd & 0x01;
		headerView.setUint8(2, byte2);

		let byte3 = 0;
		byte3 |= (message.header.ra & 0x01) << 7;
		byte3 |= (message.header.z & 0x07) << 4;
		byte3 |= message.header.rcode & 0x0f;
		headerView.setUint8(3, byte3);

		headerView.setUint16(4, message.header.qdcount, false);
		headerView.setUint16(6, message.header.ancount, false);
		headerView.setUint16(8, message.header.nscount, false);
		headerView.setUint16(10, message.header.arcount, false);

		// Generate question bytes
		const question = message.question[0]!; // Get first question from array
		const questionLength =
			question.qname.reduce((sum, label) => sum + label.length + 1, 0) + 5;
		const questionBuffer = new Uint8Array(questionLength);
		const questionView = new DataView(questionBuffer.buffer);

		let offset = 0;

		// Write labels
		for (const label of question.qname) {
			questionBuffer[offset++] = label.length;
			questionBuffer.set(label, offset);
			offset += label.length;
		}

		// Write terminator
		questionBuffer[offset++] = 0;

		// Write qtype and qclass
		questionView.setUint16(offset, question.qtype, false);
		offset += 2;
		questionView.setUint16(offset, question.qclass, false);

		// Combine header and question
		const messageBuffer = new Uint8Array(12 + questionLength);
		messageBuffer.set(new Uint8Array(headerBuffer), 0);
		messageBuffer.set(questionBuffer, 12);

		return {
			messageBuffer,
			header: message.header,
			question: question, // Return the single question object for backward compatibility
		};
	},
);

// Generate valid multi-question DNS message as Uint8Array
export const arbitraryMultiQuestionDnsMessageUint8Array = arbitraryMultiQuestionDnsMessage.map(
	(message) => {
		// Generate header bytes
		const headerBuffer = new ArrayBuffer(12);
		const headerView = new DataView(headerBuffer);

		headerView.setUint16(0, message.header.id, false);

		let byte2 = 0;
		byte2 |= (message.header.qr & 0x01) << 7;
		byte2 |= (message.header.opcode & 0x0f) << 3;
		byte2 |= (message.header.aa & 0x01) << 2;
		byte2 |= (message.header.tc & 0x01) << 1;
		byte2 |= message.header.rd & 0x01;
		headerView.setUint8(2, byte2);

		let byte3 = 0;
		byte3 |= (message.header.ra & 0x01) << 7;
		byte3 |= (message.header.z & 0x07) << 4;
		byte3 |= message.header.rcode & 0x0f;
		headerView.setUint8(3, byte3);

		headerView.setUint16(4, message.header.qdcount, false);
		headerView.setUint16(6, message.header.ancount, false);
		headerView.setUint16(8, message.header.nscount, false);
		headerView.setUint16(10, message.header.arcount, false);

		// Generate all question bytes
		const questionBuffers: Uint8Array[] = [];
		let totalQuestionLength = 0;

		for (const question of message.question) {
			const questionLength =
				question.qname.reduce((sum, label) => sum + label.length + 1, 0) + 5;
			const questionBuffer = new Uint8Array(questionLength);
			const questionView = new DataView(questionBuffer.buffer);

			let offset = 0;

			// Write labels
			for (const label of question.qname) {
				questionBuffer[offset++] = label.length;
				questionBuffer.set(label, offset);
				offset += label.length;
			}

			// Write terminator
			questionBuffer[offset++] = 0;

			// Write qtype and qclass
			questionView.setUint16(offset, question.qtype, false);
			offset += 2;
			questionView.setUint16(offset, question.qclass, false);

			questionBuffers.push(questionBuffer);
			totalQuestionLength += questionLength;
		}

		// Combine header and all questions
		const messageBuffer = new Uint8Array(12 + totalQuestionLength);
		messageBuffer.set(new Uint8Array(headerBuffer), 0);
		
		let offset = 12;
		for (const questionBuffer of questionBuffers) {
			messageBuffer.set(questionBuffer, offset);
			offset += questionBuffer.length;
		}

		return {
			messageBuffer,
			header: message.header,
			question: message.question, // Return all questions
		};
	},
);

// Generate specific test case messages for common scenarios
export const arbitraryCommonDnsMessage = fc
	.oneof(
		// A record query for example.com
		fc.constant({
			header: {
				id: 12345,
				qr: 0,
				opcode: 0,
				aa: 0,
				tc: 0,
				rd: 1,
				ra: 0,
				z: 0,
				rcode: 0,
				qdcount: 1,
				ancount: 0,
				nscount: 0,
				arcount: 0,
			},
			question: [{
				qname: [
					new Uint8Array([101, 120, 97, 109, 112, 108, 101]), // "example"
					new Uint8Array([99, 111, 109]), // "com"
				],
				qtype: RRTypeNameToRRType.A,
				qclass: 1,
			}],
		}),
		// A record query for localhost
		fc.constant({
			header: {
				id: 54321,
				qr: 0,
				opcode: 0,
				aa: 0,
				tc: 0,
				rd: 0,
				ra: 0,
				z: 0,
				rcode: 0,
				qdcount: 1,
				ancount: 0,
				nscount: 0,
				arcount: 0,
			},
			question: [{
				qname: [new Uint8Array([108, 111, 99, 97, 108, 104, 111, 115, 116])], // "localhost"
				qtype: RRTypeNameToRRType.A,
				qclass: 1,
			}],
		}),
		// MX record query for mail.example.org
		fc.constant({
			header: {
				id: 65535,
				qr: 0,
				opcode: 0,
				aa: 0,
				tc: 0,
				rd: 1,
				ra: 0,
				z: 0,
				rcode: 0,
				qdcount: 1,
				ancount: 0,
				nscount: 0,
				arcount: 0,
			},
			question: [{
				qname: [
					new Uint8Array([109, 97, 105, 108]), // "mail"
					new Uint8Array([101, 120, 97, 109, 112, 108, 101]), // "example"
					new Uint8Array([111, 114, 103]), // "org"
				],
				qtype: RRTypeNameToRRType.MX,
				qclass: 1,
			}],
		}),
	)
	.map((message) => {
		// Convert to Uint8Array format
		const headerBuffer = new ArrayBuffer(12);
		const headerView = new DataView(headerBuffer);

		headerView.setUint16(0, message.header.id, false);

		let byte2 = 0;
		byte2 |= (message.header.qr & 0x01) << 7;
		byte2 |= (message.header.opcode & 0x0f) << 3;
		byte2 |= (message.header.aa & 0x01) << 2;
		byte2 |= (message.header.tc & 0x01) << 1;
		byte2 |= message.header.rd & 0x01;
		headerView.setUint8(2, byte2);

		let byte3 = 0;
		byte3 |= (message.header.ra & 0x01) << 7;
		byte3 |= (message.header.z & 0x07) << 4;
		byte3 |= message.header.rcode & 0x0f;
		headerView.setUint8(3, byte3);

		headerView.setUint16(4, message.header.qdcount, false);
		headerView.setUint16(6, message.header.ancount, false);
		headerView.setUint16(8, message.header.nscount, false);
		headerView.setUint16(10, message.header.arcount, false);

		// Generate question bytes
		const question = message.question[0]!; // Get first question from array
		const questionLength =
			question.qname.reduce((sum, label) => sum + label.length + 1, 0) + 5;
		const questionBuffer = new Uint8Array(questionLength);
		const questionView = new DataView(questionBuffer.buffer);

		let offset = 0;

		// Write labels
		for (const label of question.qname) {
			questionBuffer[offset++] = label.length;
			questionBuffer.set(label, offset);
			offset += label.length;
		}

		// Write terminator
		questionBuffer[offset++] = 0;

		// Write qtype and qclass
		questionView.setUint16(offset, question.qtype, false);
		offset += 2;
		questionView.setUint16(offset, question.qclass, false);

		// Combine header and question
		const messageBuffer = new Uint8Array(12 + questionLength);
		messageBuffer.set(new Uint8Array(headerBuffer), 0);
		messageBuffer.set(questionBuffer, 12);

		return {
			messageBuffer,
			header: message.header,
			question: question, // Return the single question object for backward compatibility
		};
	});

// Generate DNS messages with count mismatches for error testing
export const arbitraryCountMismatchDnsMessage = fc
	.record({
		header: arbitraryValidQuestionDnsHeader,
		actualQuestionCount: fc.integer({ min: 0, max: 2 }),
		claimedQuestionCount: fc.integer({ min: 1, max: 5 }),
	})
	.filter(({ actualQuestionCount, claimedQuestionCount }) => 
		actualQuestionCount !== claimedQuestionCount
	)
	.chain(({ header, actualQuestionCount, claimedQuestionCount }) => {
		// Generate only actualQuestionCount questions but claim claimedQuestionCount
		return fc.array(arbitraryValidDnsQuestion, { 
			minLength: actualQuestionCount, 
			maxLength: actualQuestionCount 
		}).map(questions => {
			const updatedHeader = {
				...header,
				qdcount: claimedQuestionCount, // Mismatch: claim more/fewer than actual
				ancount: 0,
				nscount: 0,
				arcount: 0,
			};
			return { header: updatedHeader, question: questions };
		});
	});

// Generate count mismatch message as Uint8Array for testing
export const arbitraryCountMismatchDnsMessageUint8Array = arbitraryCountMismatchDnsMessage.map(
	(message) => {
		// Generate header bytes with mismatched count
		const headerBuffer = new ArrayBuffer(12);
		const headerView = new DataView(headerBuffer);

		headerView.setUint16(0, message.header.id, false);

		let byte2 = 0;
		byte2 |= (message.header.qr & 0x01) << 7;
		byte2 |= (message.header.opcode & 0x0f) << 3;
		byte2 |= (message.header.aa & 0x01) << 2;
		byte2 |= (message.header.tc & 0x01) << 1;
		byte2 |= message.header.rd & 0x01;
		headerView.setUint8(2, byte2);

		let byte3 = 0;
		byte3 |= (message.header.ra & 0x01) << 7;
		byte3 |= (message.header.z & 0x07) << 4;
		byte3 |= message.header.rcode & 0x0f;
		headerView.setUint8(3, byte3);

		headerView.setUint16(4, message.header.qdcount, false); // Mismatched count
		headerView.setUint16(6, message.header.ancount, false);
		headerView.setUint16(8, message.header.nscount, false);
		headerView.setUint16(10, message.header.arcount, false);

		// Generate only the actual questions (not the claimed count)
		const questionBuffers: Uint8Array[] = [];
		let totalQuestionLength = 0;

		for (const question of message.question) {
			const questionLength =
				question.qname.reduce((sum, label) => sum + label.length + 1, 0) + 5;
			const questionBuffer = new Uint8Array(questionLength);
			const questionView = new DataView(questionBuffer.buffer);

			let offset = 0;

			// Write labels
			for (const label of question.qname) {
				questionBuffer[offset++] = label.length;
				questionBuffer.set(label, offset);
				offset += label.length;
			}

			// Write terminator
			questionBuffer[offset++] = 0;

			// Write qtype and qclass
			questionView.setUint16(offset, question.qtype, false);
			offset += 2;
			questionView.setUint16(offset, question.qclass, false);

			questionBuffers.push(questionBuffer);
			totalQuestionLength += questionLength;
		}

		// Combine header and actual questions
		const messageBuffer = new Uint8Array(12 + totalQuestionLength);
		messageBuffer.set(new Uint8Array(headerBuffer), 0);
		
		let offset = 12;
		for (const questionBuffer of questionBuffers) {
			messageBuffer.set(questionBuffer, offset);
			offset += questionBuffer.length;
		}

		return {
			messageBuffer,
			header: message.header,
			question: message.question,
			actualCount: message.question.length,
			claimedCount: message.header.qdcount,
		};
	},
);
