import { ParseResult, Schema } from "effect";
import type { Mutable } from "effect/Types";

const Nibble = Schema.Number.pipe(
	Schema.between(0, 15, {
		identifier: "Nibble",
		description: "a 4-bit unsigned integer",
	}),
);

const Uint3 = Schema.Number.pipe(
	Schema.between(0, 7, {
		identifier: "Uint3",
		description: "a 3-bit unsigned integer",
	}),
);

type Bit = typeof Bit.Type;

const Bit = Schema.Literal(0, 1).annotations({
	identifier: "Bit",
	description: "a 1-bit unsigned integer",
});

const Uint8 = Schema.Number.pipe(
	Schema.between(0, 255, {
		identifier: "Byte",
		description: "a 8-bit unsigned integer",
	}),
);

const Uint16 = Schema.Number.pipe(
	Schema.between(0, 65_535, {
		identifier: "Uint16",
		description: "a 16-bit unsigned integer",
	}),
);

const Int32 = Schema.Number.pipe(
	Schema.between(-2_147_483_648, 2_147_483_647, {
		identifier: "Int32",
		description: "a 32-bit signed integer",
	}),
);

/* 2.3.4. Size limits
 *
 * Various objects and parameters in the DNS have size limits.  They are
 * listed below.  Some could be easily changed, others are more
 * fundamental.
 *
 * labels          63 octets or less
 * names           255 octets or less
 * TTL             positive values of a signed 32 bit number.
 * UDP messages    512 octets or less
 *
 * @see https://www.rfc-editor.org/rfc/rfc1035.html#section-2.3.4
 */
const Label = Schema.Uint8ArrayFromSelf.pipe(
	// @ts-expect-error
	Schema.maxItems(63),
	Schema.annotations({
		identifier: "Label",
		description: "63 octets or less",
	}),
);

type Name = typeof Name.Type;
const Name = Schema.Array(Schema.Uint8ArrayFromSelf)
	.pipe(Schema.maxItems(255))
	.annotations({ identifier: "Name", description: "255 octets or less" });

const Ttl = Int32.pipe(Schema.positive()).annotations({
	identifier: "Ttl",
	description: "positive values of a signed 32 bit number",
});

const UdpMessages = Schema.Array(Uint8).pipe(Schema.maxItems(63)).annotations({
	identifier: "UdpMessages",
	description: "512 octets or less",
});

/**
 * 3.2.2. TYPE values
 *
 * TYPE fields are used in resource records. Note that these types are a
 * subset of QTYPEs.
 *
 * @see https://www.rfc-editor.org/rfc/rfc1035.html#section-3.2.2
 */
export const DnsType = {
	/** A host address */
	A: 1,
	/** An authoritative name server */
	NS: 2,
	/** A mail destination (Obsolete - use MX) */
	MD: 3,
	/** A mail forwarder (Obsolete - use MX) */
	MF: 4,
	/** The canonical name for an alias */
	CNAME: 5,
	/** Marks the start of a zone of authority */
	SOA: 6,
	/** A mailbox domain name (EXPERIMENTAL) */
	MB: 7,
	/** A mail group member (EXPERIMENTAL) */
	MG: 8,
	/** A mail rename domain name (EXPERIMENTAL) */
	MR: 9,
	/** A null RR (EXPERIMENTAL) */
	NULL: 10,
	/** A well known service description */
	WKS: 11,
	/** A domain name pointer */
	PTR: 12,
	/** Host information */
	HINFO: 13,
	/** Mailbox or mail list information */
	MINFO: 14,
	/** Mail exchange */
	MX: 15,
	/** Text strings */
	TXT: 16,
} as const;

export type DnsType = (typeof DnsType)[keyof typeof DnsType];

export interface Message {
	header: Header;
	question: Question;
	answer: void;
	authority: void;
	additional: void;
}

/**
 * 4.1.1. Header section format
 *
 * The header contains the following fields:
 *
 *                                    1  1  1  1  1  1
 *      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                      ID                       |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    QDCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    ANCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    NSCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    ARCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * @see https://www.rfc-editor.org/rfc/rfc1035.html#section-4.1.1
 */
export const Header = Schema.Struct({
	/**
	 * A 16 bit identifier assigned by the program that
	 * generates any kind of query.  This identifier is copied
	 * the corresponding reply and can be used by the requester
	 * to match up replies to outstanding queries.
	 */
	id: Uint16,

	/**
	 * A one bit field that specifies whether this message is a
	 * query (0), or a response (1).
	 */
	qr: Bit,

	/**
	 * A four bit field that specifies the kind of query in this message.
	 * This value is set by the originator of a query and copied into the response.
	 * The values are:
	 *
	 * 0   - a standard query (QUERY)
	 * 1   - an inverse query (IQUERY)
	 * 2   - a server status request (STATUS)
	 * 3-15 - reserved for future use
	 */
	opcode: Nibble,

	/**
	 * Authoritative Answer - this bit is valid in responses,
	 * and specifies that the responding name server is an
	 * authority for the domain name in question section.
	 * Note that the contents of the answer section may have
	 * multiple owner names because of aliases. The AA bit
	 * corresponds to the name which matches the query name, or
	 * the first owner name in the answer section.
	 */
	aa: Bit,

	/**
	 * TrunCation - specifies that this message was truncated
	 * due to length greater than that permitted on the
	 * transmission channel.
	 */
	tc: Bit,

	/**
	 * Recursion Desired - this bit may be set in a query and
	 * is copied into the response. If RD is set, it directs
	 * the name server to pursue the query recursively.
	 * Recursive query support is optional.
	 */
	rd: Bit,

	/**
	 * Recursion Available - this bit is set or cleared in a
	 * response, and denotes whether recursive query support is
	 * available in the name server.
	 */
	ra: Bit,

	/**
	 * Reserved for future use. Must be zero in all queries
	 * and responses.
	 */
	z: Uint3,

	/**
	 * Response code - this 4 bit field is set as part of
	 * responses. The values have the following interpretation:
	 * 0   - No error condition
	 * 1   - Format error (unable to interpret the query)
	 * 2   - Server failure (problem with the name server)
	 * 3   - Name Error (domain name referenced in the query does not exist)
	 * 4   - Not Implemented (unsupported kind of query)
	 * 5   - Refused (operation refused for policy reasons)
	 * 6-15 - Reserved for future use
	 */
	rcode: Nibble,

	/**
	 * An unsigned 16 bit integer specifying the number of
	 * entries in the question section.
	 */
	qdcount: Uint16,

	/**
	 * An unsigned 16 bit integer specifying the number of
	 * resource records in the answer section.
	 */
	ancount: Uint16,

	/**
	 * An unsigned 16 bit integer specifying the number of name
	 * server resource records in the authority records section.
	 */
	nscount: Uint16,

	/**
	 * An unsigned 16 bit integer specifying the number of
	 * resource records in the additional records section.
	 */
	arcount: Uint16,
});

export interface Header extends Schema.Schema.Type<typeof Header> {}

export const HeaderFromUint8Array = Schema.transformOrFail(
	Schema.Uint8ArrayFromSelf,
	Header,
	{
		strict: true,
		decode(uint8Array, _, ast) {
			if (uint8Array.length !== 12) {
				return ParseResult.fail(
					new ParseResult.Type(
						ast,
						uint8Array,
						`Header must be 12 bytes, received ${uint8Array.length}`,
					),
				);
			}
			const dataView = new DataView(
				uint8Array.buffer,
				uint8Array.byteOffset,
				uint8Array.byteLength,
			);

			const header = Header.make({
				id: dataView.getUint16(0, false),
				qr: ((dataView.getUint8(2) >> 7) & 0x01) as Bit,
				opcode: ((dataView.getUint8(2) >> 3) & 0x0f) as Bit,
				aa: ((dataView.getUint8(2) >> 2) & 0x01) as Bit,
				tc: ((dataView.getUint8(2) >> 1) & 0x01) as Bit,
				rd: (dataView.getUint8(2) & 0x01) as Bit,
				ra: ((dataView.getUint8(3) >> 7) & 0x01) as Bit,
				z: (dataView.getUint8(3) >> 4) & 0x07,
				rcode: dataView.getUint8(3) & 0x0f,
				qdcount: dataView.getUint16(4, false),
				ancount: dataView.getUint16(6, false),
				nscount: dataView.getUint16(8, false),
				arcount: dataView.getUint16(10, false),
			});

			return ParseResult.succeed(header);
		},
		encode(header) {
			const buffer = new ArrayBuffer(12);
			const dataView = new DataView(buffer);

			dataView.setUint16(0, header.id);

			let byte2 = 0;
			byte2 |= (header.qr & 0x01) << 7;
			byte2 |= (header.opcode & 0x0f) << 3;
			byte2 |= (header.aa & 0x01) << 2;
			byte2 |= (header.tc & 0x01) << 1;
			byte2 |= header.rd & 0x01;
			dataView.setUint8(2, byte2);

			let byte3 = 0;
			byte3 |= (header.ra & 0x01) << 7;
			byte3 |= (header.z & 0x07) << 4;
			byte3 |= header.rcode & 0x0f;
			dataView.setUint8(3, byte3);

			dataView.setUint16(4, header.qdcount);
			dataView.setUint16(6, header.ancount);
			dataView.setUint16(8, header.nscount);
			dataView.setUint16(10, header.arcount);

			return ParseResult.succeed(new Uint8Array(buffer));
		},
	},
);

export const decodeHeader = Schema.decode(HeaderFromUint8Array);
export const encodeHeader = Schema.encode(HeaderFromUint8Array);

export const decodeSyncHeader = Schema.decodeSync(HeaderFromUint8Array);
export const encodeSyncHeader = Schema.encodeSync(HeaderFromUint8Array);

/**
 * 4.1.2. Question section format
 *
 * The question section is used to carry the "question" in most queries,
 * i.e., the parameters that define what is being asked. The section
 * contains QDCOUNT (usually 1) entries, each of the following format:
 *
 *                               1  1  1  1  1  1
 * 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                                               |
 * /                     QNAME                     /
 * /                                               /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     QTYPE                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     QCLASS                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * @see https://www.rfc-editor.org/rfc/rfc1035.html#section-4.1.2
 */
export const Question = Schema.Struct({
	/**
	 * A domain name represented as a sequence of labels, where
	 * each label consists of a length octet followed by that
	 * number of octets. The domain name terminates with the
	 * zero length octet for the null label of the root. Note
	 * that this field may be an odd number of octets; no
	 * padding is used.
	 */
	qname: Name,

	/**
	 * A two octet code which specifies the type of the query.
	 * The values for this field include all codes valid for a
	 * TYPE field, together with some more general codes which
	 * can match more than one type of RR.
	 */
	qtype: Uint16,

	/**
	 * A two octet code that specifies the class of the query.
	 * For example, the QCLASS field is IN for the Internet.
	 */
	qclass: Uint16,
});

export type Question = typeof Question.Type;

export const QuestionFromUint8Array = Schema.transformOrFail(
	Schema.Uint8ArrayFromSelf,
	Question,
	{
		strict: true,
		decode(uint8Array, _, ast) {
			if (uint8Array.length < 5) {
				return ParseResult.fail(
					new ParseResult.Type(
						ast,
						uint8Array,
						`Question must have a minimum length of 5 bytes, received ${uint8Array.length}`,
					),
				);
			}

			if (uint8Array.length > 260) {
				return ParseResult.fail(
					new ParseResult.Type(
						ast,
						uint8Array,
						`Question must have a maximum length of 260 bytes, received ${uint8Array.length}`,
					),
				);
			}
			const dataView = new DataView(
				uint8Array.buffer,
				uint8Array.byteOffset,
				uint8Array.byteLength,
			);

			let qname: Mutable<Name> = [];
			let offset = 0;

			while (true) {
				const length = dataView.getUint8(offset);

				// null terminating byte
				if (length === 0) {
					offset += 1;
					break;
				}

				if (offset + 1 + length > uint8Array.length) {
					return ParseResult.fail(
						new ParseResult.Type(
							ast,
							uint8Array,
							`QNAME label overruns buffer at offset ${offset}`,
						),
					);
				}

				const value = uint8Array.subarray(offset + 1, offset + 1 + length);

				if (value.length > 63) {
					return ParseResult.fail(
						new ParseResult.Type(
							ast,
							uint8Array,
							`QNAME label must be 63 bytes or less, received ${value.length}`,
						),
					);
				}
				qname.push(value);
				offset += length + 1;
			}

			if (offset + 4 > uint8Array.length) {
				return ParseResult.fail(
					new ParseResult.Type(
						ast,
						uint8Array,
						`Not enough bytes for QTYPE and QCLASS after QNAME`,
					),
				);
			}

			const question = Question.make({
				qname,
				qtype: dataView.getUint16(offset, false),
				qclass: dataView.getUint16(offset + 2, false),
			});

			return ParseResult.succeed(question);
		},
		encode(header, _, ast) {
			/** 1 zero byte (QNAME terminator) + 4 bytes for QTYPE & QCLASS */
			const terminatorAndQFieldsLength = 5;
			let bufferLength = terminatorAndQFieldsLength;

			for (let idx = 0; idx < header.qname.length; idx++) {
				const labelLength = header.qname[idx]?.length ?? 0;

				if (labelLength > 63) {
					return ParseResult.fail(
						new ParseResult.Type(
							ast,
							header,
							`QNAME label must be 63 bytes or less, received ${labelLength}`,
						),
					);
				}

				bufferLength += 1 + labelLength;
			}

			const buffer = new ArrayBuffer(bufferLength);
			const out = new Uint8Array(buffer);
			const dataView = new DataView(out.buffer);

			let writeOffset = 0;

			for (const label of header.qname) {
				dataView.setUint8(writeOffset++, label.length);
				out.set(label, writeOffset);
				writeOffset += label.length;
			}

			// terminating zero for QNAME
			dataView.setUint8(writeOffset++, 0x00);

			dataView.setUint16(writeOffset, header.qtype, false);
			writeOffset += 2;

			dataView.setUint16(writeOffset, header.qclass, false);

			return ParseResult.succeed(new Uint8Array(buffer));
		},
	},
);

export const decodeQuestion = Schema.decode(QuestionFromUint8Array);
export const encodeQuestion = Schema.encode(QuestionFromUint8Array);

export const decodeSyncQuestion = Schema.decodeSync(QuestionFromUint8Array);
export const encodeSyncQuestion = Schema.encodeSync(QuestionFromUint8Array);

// Example DNS header (12 bytes) as a Uint8Array
// Fields: ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
// Let's use: ID=0x1234, QR=0, Opcode=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0
// QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0

const mockDnsHeader = new Uint8Array([
	0x12,
	0x34, // ID: 0x1234
	0x01,
	0x00, // Flags: 0000 0001 0000 0000 (RD=1)
	0x00,
	0x01, // QDCOUNT: 1
	0x00,
	0x00, // ANCOUNT: 0
	0x00,
	0x00, // NSCOUNT: 0
	0x00,
	0x00, // ARCOUNT: 0
]);

const dnsQuestion = new Uint8Array([
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
