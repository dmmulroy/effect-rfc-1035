import { Effect, ParseResult, Schema } from "effect";

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

const Uint16 = Schema.Number.pipe(
	Schema.between(0, 65_535, {
		identifier: "Uint16",
		description: "a 16-bit unsigned integer",
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
 */

export interface Message {
	header: Header;
	question: void;
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

const _ = ParseResult.flatMap(() => ParseResult.succeed({}));

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
						`Header must be 12 bytes, found ${uint8Array.length}`,
					),
				);
			}
			const dataView = new DataView(uint8Array.buffer);

			const header = Header.make({
				id: dataView.getUint16(0),
				qr: ((dataView.getUint8(2) >> 7) & 0x01) as Bit,
				opcode: ((dataView.getUint8(2) >> 3) & 0x0f) as Bit,
				aa: ((dataView.getUint8(2) >> 2) & 0x01) as Bit,
				tc: ((dataView.getUint8(2) >> 1) & 0x01) as Bit,
				rd: (dataView.getUint8(2) & 0x01) as Bit,
				ra: ((dataView.getUint8(3) >> 7) & 0x01) as Bit,
				z: (dataView.getUint8(3) >> 4) & 0x07,
				rcode: dataView.getUint8(3) & 0x0f,
				qdcount: dataView.getUint16(4),
				ancount: dataView.getUint16(6),
				nscount: dataView.getUint16(8),
				arcount: dataView.getUint16(10),
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
