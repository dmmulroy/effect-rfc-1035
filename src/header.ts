import { Either, ParseResult, Schema } from "effect";
import { Bit, Nibble, Uint16, Uint3 } from "./types";
import { getUint8, getUint16 } from "./utils";

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
			if (uint8Array.byteLength !== 12) {
				return ParseResult.fail(
					new ParseResult.Type(
						ast,
						uint8Array,
						`Header must be 12 bytes, received ${uint8Array.byteLength}`,
					),
				);
			}
			const dataView = new DataView(
				uint8Array.buffer,
				uint8Array.byteOffset,
				uint8Array.byteLength,
			);

			const idResult = getUint16(dataView, 0, ast);
			if (Either.isLeft(idResult)) {
				return ParseResult.fail(idResult.left);
			}

			const byte2Result = getUint8(dataView, 2, ast);
			if (Either.isLeft(byte2Result)) {
				return ParseResult.fail(byte2Result.left);
			}

			const byte3Result = getUint8(dataView, 3, ast);
			if (Either.isLeft(byte3Result)) {
				return ParseResult.fail(byte3Result.left);
			}

			const qdcountResult = getUint16(dataView, 4, ast);
			if (Either.isLeft(qdcountResult)) {
				return ParseResult.fail(qdcountResult.left);
			}

			const ancountResult = getUint16(dataView, 6, ast);
			if (Either.isLeft(ancountResult)) {
				return ParseResult.fail(ancountResult.left);
			}

			const nscountResult = getUint16(dataView, 8, ast);
			if (Either.isLeft(nscountResult)) {
				return ParseResult.fail(nscountResult.left);
			}

			const arcountResult = getUint16(dataView, 10, ast);
			if (Either.isLeft(arcountResult)) {
				return ParseResult.fail(arcountResult.left);
			}

			const byte2 = byte2Result.right;
			const byte3 = byte3Result.right;

			const qr = ((byte2 >> 7) & 0x01) as Bit;
			const opcode = ((byte2 >> 3) & 0x0f) as Bit;
			const aa = ((byte2 >> 2) & 0x01) as Bit;
			const z = (byte3 >> 4) & 0x07;
			const rcode = byte3 & 0x0f;

			if (opcode > 2) {
				return ParseResult.fail(
					new ParseResult.Type(
						ast,
						opcode,
						`Opcode must be 0, 1, or 2. Recievied '${opcode}'`,
					),
				);
			}

			if (qr === 0 && aa === 1) {
				return ParseResult.fail(
					new ParseResult.Type(
						ast,
						aa,
						`Authoritative Answer bit should be 0 for questions, recieved 1`,
					),
				);
			}

			if (z !== 0) {
				return ParseResult.fail(
					new ParseResult.Type(ast, z, `Z must be 0. Recievied '${z}'`),
				);
			}

			if (rcode > 5) {
				return ParseResult.fail(
					new ParseResult.Type(
						ast,
						rcode,
						`RCODE must be 0, 1, 2, 3, 4, or 5. Recievied '${opcode}'`,
					),
				);
			}

			const header = Header.make({
				id: idResult.right,
				qr: ((byte2 >> 7) & 0x01) as Bit,
				opcode,
				aa: ((byte2 >> 2) & 0x01) as Bit,
				tc: ((byte2 >> 1) & 0x01) as Bit,
				rd: (byte2 & 0x01) as Bit,
				ra: ((byte3 >> 7) & 0x01) as Bit,
				z: (byte3 >> 4) & 0x07,
				rcode: byte3 & 0x0f,
				qdcount: qdcountResult.right,
				ancount: ancountResult.right,
				nscount: nscountResult.right,
				arcount: arcountResult.right,
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
