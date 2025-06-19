import { Either, ParseResult, Schema, SchemaAST } from "effect";
import { uint8Array } from "effect/FastCheck";
import { isError } from "effect/Predicate";
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

type Uint8 = typeof Uint8.Type;

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

type Uint31 = typeof Uint31.Type;
const Uint31 = Schema.Number.pipe(
	Schema.between(0, 2_147_483_647, {
		identifier: "Uint31",
		description: "a 31-bit unsigned integer",
	}),
);

function isUint31(num: number): num is Uint31 {
	return Schema.is(Uint31)(num);
}

/* 2.3.4. Size limits
 *
 * Various objects and parameters in the DNS have size limits.  They are
 * listed below.  Some could be easily changed, others are more
 * fundamental.
 *
 * labels          63 octets or less
 * names           255 octets or less
 * TTL             31 bit unsigned integer
 * UDP messages    512 octets or less
 *
 * @see https://www.rfc-editor.org/rfc/rfc1035.html#section-2.3.4
 * @see https://datatracker.ietf.org/doc/html/rfc2181#section-8
 */

/** Label */
const Label = Schema.Uint8ArrayFromSelf.pipe(
	// @ts-expect-error
	Schema.maxItems(63),
	Schema.annotations({
		identifier: "Label",
		description: "63 octets or less",
	}),
);

/** `Uint8Array` containting 255 octets or less */
type Name = typeof Name.Type;

const Name = Schema.Array(Schema.Uint8ArrayFromSelf)
	.pipe(Schema.maxItems(255))
	.annotations({ identifier: "Name", description: "255 octets or less" });

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

			const header = Header.make({
				id: idResult.right,
				qr: ((byte2 >> 7) & 0x01) as Bit,
				opcode: ((byte2 >> 3) & 0x0f) as Bit,
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
			let qnameSize = 0;

			while (true) {
				const lengthResult = getUint8(dataView, offset, ast);
				if (Either.isLeft(lengthResult)) {
					return ParseResult.fail(lengthResult.left);
				}
				const length = lengthResult.right;

				// null terminating byte
				if (length === 0) {
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

				const label = uint8Array.subarray(offset + 1, offset + 1 + length);

				if (label.length > 63) {
					return ParseResult.fail(
						new ParseResult.Type(
							ast,
							uint8Array,
							`QNAME label must be 63 bytes or less, received ${label.length}`,
						),
					);
				}

				qnameSize += label.buffer.byteLength;

				if (qnameSize > 255) {
					return ParseResult.fail(
						new ParseResult.Type(
							ast,
							uint8Array,
							`QNAME exceeded maximum size of 255 bytes`,
						),
					);
				}
				qname.push(label);
				offset += length + 1;
			}

			// Increment to the next byte
			offset += 1;

			if (offset + 4 > uint8Array.length) {
				return ParseResult.fail(
					new ParseResult.Type(
						ast,
						uint8Array,
						`Not enough bytes for QTYPE and QCLASS after QNAME`,
					),
				);
			}

			const qtypeResult = getUint16(dataView, offset, ast);
			if (Either.isLeft(qtypeResult)) {
				return ParseResult.fail(qtypeResult.left);
			}
			const qtype = qtypeResult.right;

			const qclassResult = getUint16(dataView, offset + 2, ast);
			if (Either.isLeft(qclassResult)) {
				return ParseResult.fail(qclassResult.left);
			}
			const qclass = qclassResult.right;

			const question = Question.make({
				qname,
				qtype,
				qclass,
			});

			return ParseResult.succeed(question);
		},
		encode(question, _, ast) {
			/** 1 zero byte (QNAME terminator) + 4 bytes for QTYPE & QCLASS */
			const terminatorAndQFieldsLength = 5;
			let bufferLength = terminatorAndQFieldsLength;

			if (question.qname.length > 255) {
				return ParseResult.fail(
					new ParseResult.Type(
						ast,
						question,
						`QNAME length must be 255 bytes or less, received ${question.qname.length}`,
					),
				);
			}

			let qnameSize = 0;
			for (let idx = 0; idx < question.qname.length; idx++) {
				const labelLength = question.qname[idx]?.length ?? 0;

				if (labelLength > 63) {
					return ParseResult.fail(
						new ParseResult.Type(
							ast,
							question,
							`QNAME label must be 63 bytes or less, received ${labelLength}`,
						),
					);
				}

				bufferLength += 1 + labelLength;
				qnameSize += labelLength;

				if (qnameSize > 255) {
					return ParseResult.fail(
						new ParseResult.Type(
							ast,
							uint8Array,
							`QNAME exceeded maximum size of 255 bytes`,
						),
					);
				}
			}

			const buffer = new ArrayBuffer(bufferLength);
			const out = new Uint8Array(buffer);
			const dataView = new DataView(out.buffer);

			let writeOffset = 0;

			for (const label of question.qname) {
				dataView.setUint8(writeOffset++, label.length);
				out.set(label, writeOffset);
				writeOffset += label.length;
			}

			// terminating zero for QNAME
			dataView.setUint8(writeOffset++, 0x00);

			dataView.setUint16(writeOffset, question.qtype, false);
			writeOffset += 2;

			dataView.setUint16(writeOffset, question.qclass, false);

			return ParseResult.succeed(new Uint8Array(buffer));
		},
	},
);

export const decodeQuestion = Schema.decode(QuestionFromUint8Array);
export const encodeQuestion = Schema.encode(QuestionFromUint8Array);

export const decodeSyncQuestion = Schema.decodeSync(QuestionFromUint8Array);
export const encodeSyncQuestion = Schema.encodeSync(QuestionFromUint8Array);

/**
 * 4.1.3. Resource record format
 *
 * The answer, authority, and additional sections all share the same
 * format: a variable number of resource records, where the number of
 * records is specified in the corresponding count field in the header.
 * Each resource record has the following format:
 *
 *                                      1  1  1  1  1  1
 *        0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *      |                                               |
 *      /                                               /
 *      /                      NAME                     /
 *      |                                               |
 *      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *      |                      TYPE                     |
 *      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *      |                     CLASS                     |
 *      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *      |                      TTL                      |
 *      |                                               |
 *      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *      |                   RDLENGTH                    |
 *      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
 *      /                     RDATA                     /
 *      /                                               /
 *      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * where:
 *
 * NAME            a domain name to which this resource record pertains.
 *
 * TYPE            two octets containing one of the RR type codes.  This
 *                 field specifies the meaning of the data in the RDATA
 *                 field.
 *
 * CLASS           two octets which specify the class of the data in the
 *                 RDATA field.
 *
 * TTL             a 31 bit unsigned integer that specifies the time
 *                 interval (in seconds) that the resource record may be
 *                 cached before it should be discarded.  Zero values are
 *                 interpreted to mean that the RR can only be used for the
 *                 transaction in progress, and should not be cached.
 *
 * RDLENGTH        an unsigned 16 bit integer that specifies the length in
 *                 octets of the RDATA field.
 *
 * RDATA           a variable length string of octets that describes the
 *                 resource.  The format of this information varies
 *                 according to the TYPE and CLASS of the resource record.
 *                 For example, if the TYPE is A and the CLASS is IN,
 *                 the RDATA field is a 4 octet ARPA Internet address.
 */
const ResourceRecord = Schema.Struct({
	name: Name,
	type: Uint16,
	class: Uint16,
	ttl: Uint31,
	rdlength: Uint16,
	rdata: Schema.Uint8ArrayFromSelf,
});

export type ResourceRecord = typeof ResourceRecord.Type;

export const ResourceRecordFromUint8Array = Schema.transformOrFail(
	Schema.Uint8ArrayFromSelf,
	ResourceRecord,
	{
		strict: true,
		decode(uint8Array, _, ast) {
			const dataView = new DataView(
				uint8Array.buffer,
				uint8Array.byteOffset,
				uint8Array.byteLength,
			);

			let name: Mutable<Name> = [];
			let offset = 0;
			let nameSize = 0;

			while (true) {
				const byteResult = ParseResult.try({
					try: () => dataView.getUint8(offset),
					catch(cause) {
						return new ParseResult.Type(
							ast,
							dataView,
							isError(cause) ? cause.message : "Malformed input",
						);
					},
				});

				if (Either.isLeft(byteResult)) {
					return ParseResult.fail(byteResult.left);
				}

				const byte = byteResult.right;

				// null terminating byte
				if (byte === 0x00) {
					offset += 1;

					break;
				}

				if (offset + 1 + byte > uint8Array.length) {
					return ParseResult.fail(
						new ParseResult.Type(
							ast,
							uint8Array,
							`NAME label overruns buffer at offset ${offset}`,
						),
					);
				}

				const label = uint8Array.subarray(offset + 1, offset + 1 + byte);

				if (label.length > 63) {
					return ParseResult.fail(
						new ParseResult.Type(
							ast,
							uint8Array,
							`NAME label must be 63 bytes or less, received ${label.length}`,
						),
					);
				}

				nameSize += label.byteLength;

				if (nameSize > 255) {
					return ParseResult.fail(
						new ParseResult.Type(
							ast,
							uint8Array,
							`QNAME exceeded maximum size of 255 bytes`,
						),
					);
				}

				name.push(label);
				offset += byte + 1;
			}

			// offset 46,
			const typeResult = getUint16(dataView, offset, ast);
			if (Either.isLeft(typeResult)) {
				return ParseResult.fail(typeResult.left);
			}
			const type = typeResult.right;
			offset += 2;

			const resourceClassResult = getUint16(dataView, offset, ast);
			if (Either.isLeft(resourceClassResult)) {
				return ParseResult.fail(resourceClassResult.left);
			}
			const resourceClass = resourceClassResult.right;
			offset += 2;

			const ttlResult = getUint32(dataView, offset, ast);
			if (Either.isLeft(ttlResult)) {
				return ParseResult.fail(ttlResult.left);
			}
			const ttl = ttlResult.right;
			offset += 4;

			if (!isUint31(ttl)) {
				return ParseResult.fail(
					new ParseResult.Type(
						ast,
						ttl,
						`TTL must be a 31-bit unsigned integer, received '${ttl}'`,
					),
				);
			}

			const rdlengthResult = getUint16(dataView, offset, ast);
			if (Either.isLeft(rdlengthResult)) {
				return ParseResult.fail(rdlengthResult.left);
			}
			const rdlength = rdlengthResult.right;
			offset += 2;

			const rdata: Uint8Array = uint8Array.subarray(offset, offset + rdlength);

			if (rdata.byteLength !== rdlength) {
				return ParseResult.fail(
					new ParseResult.Type(
						ast,
						uint8Array,
						`RDATA length did not match RDLENGTH. Expected '${rdlength}, received '${rdata.byteLength}'`,
					),
				);
			}

			const resourceRecord = ResourceRecord.make({
				name,
				type,
				class: resourceClass,
				ttl,
				rdlength,
				rdata,
			});

			return ParseResult.succeed(resourceRecord);
		},
		encode(resourceRecord, _, ast) {
			/** 1 zero byte (NAME terminator) + type + class + ttl + rdlength + rdata */
			let bufferLength = 1 + 2 + 2 + 4 + 2 + resourceRecord.rdlength;

			if (resourceRecord.name.length > 255) {
				return ParseResult.fail(
					new ParseResult.Type(
						ast,
						resourceRecord,
						`NAME length must be 255 bytes or less, received ${resourceRecord.name.length}`,
					),
				);
			}

			let nameSize = 0;
			for (let idx = 0; idx < resourceRecord.name.length; idx++) {
				const labelLength = resourceRecord.name[idx]?.length ?? 0;

				if (labelLength > 63) {
					return ParseResult.fail(
						new ParseResult.Type(
							ast,
							resourceRecord,
							`NAME label must be 63 bytes or less, received ${labelLength}`,
						),
					);
				}

				bufferLength += 1 + labelLength;
				nameSize += labelLength;
				if (nameSize > 255) {
					return ParseResult.fail(
						new ParseResult.Type(
							ast,
							uint8Array,
							`QNAME exceeded maximum size of 255 bytes`,
						),
					);
				}
			}

			const buffer = new ArrayBuffer(bufferLength);
			const out = new Uint8Array(buffer);
			const dataView = new DataView(out.buffer);

			let writeOffset = 0;

			for (const label of resourceRecord.name) {
				dataView.setUint8(writeOffset++, label.length);
				out.set(label, writeOffset);
				writeOffset += label.length;
			}

			// terminating zero for NAME
			dataView.setUint8(writeOffset++, 0x00);

			dataView.setUint16(writeOffset, resourceRecord.type, false);

			dataView.setUint16((writeOffset += 2), resourceRecord.class, false);

			dataView.setUint32((writeOffset += 2), resourceRecord.ttl, false);

			dataView.setUint16((writeOffset += 4), resourceRecord.rdlength, false);

			out.set(resourceRecord.rdata, (writeOffset += 2));

			return ParseResult.succeed(new Uint8Array(buffer));
		},
	},
);

export const decodeResourceRecord = Schema.decode(ResourceRecordFromUint8Array);
export const encodeResourceRecord = Schema.encode(ResourceRecordFromUint8Array);

// if (isPointer) {
// 	const pointerOffset =
// 		(dataView.getUint16(offset, false) << 0x14) >>> 0x14;
//
// 	let previousOffset = 0;
//
// 	const previousUint8Array = uint8Array.subarray(pointerOffset, offset);
//
// 	const previousDataView = new DataView(
// 		previousUint8Array.buffer,
// 		previousUint8Array.byteOffset,
// 		previousUint8Array.byteLength,
// 	);
//
// 	while (true) {
// 		const previousLength = previousDataView.getUint8(offset);
//
// 		// found the null terminating byte
// 		if (previousLength === 0) {
// 			break;
// 		}
//
// 		if (
// 			previousOffset + 1 + previousLength >
// 			previousUint8Array.length
// 		) {
// 			return ParseResult.fail(
// 				new ParseResult.Type(
// 					ast,
// 					previousUint8Array,
// 					`NAME label overruns buffer at offset ${previousOffset}`,
// 				),
// 			);
// 		}
//
// 		const value = previousUint8Array.subarray(
// 			previousOffset + 1,
// 			previousOffset + 1 + previousLength,
// 		);
//
// 		if (value.length > 63) {
// 			return ParseResult.fail(
// 				new ParseResult.Type(
// 					ast,
// 					previousOffset,
// 					`NAME label must be 63 bytes or less, received ${value.length}`,
// 				),
// 			);
// 		}
//
// 		name.push(value);
// 		previousOffset += previousLength + 1;
// 	}
//
// 	offset += 2;
// 	break;
// }

function getUint8(
	dataView: DataView,
	offset: number,
	ast: SchemaAST.AST,
): Either.Either<number, ParseResult.ParseIssue> {
	return ParseResult.try({
		try: () => dataView.getUint8(offset),
		catch(cause) {
			return new ParseResult.Type(
				ast,
				dataView,
				isError(cause) ? cause.message : "Malformed input",
			);
		},
	});
}

function getUint16(
	dataView: DataView,
	offset: number,
	ast: SchemaAST.AST,
): Either.Either<number, ParseResult.ParseIssue> {
	return ParseResult.try({
		try: () => dataView.getUint16(offset, false),
		catch(cause) {
			return new ParseResult.Type(
				ast,
				dataView,
				isError(cause) ? cause.message : "Malformed input",
			);
		},
	});
}

function getUint32(
	dataView: DataView,
	offset: number,
	ast: SchemaAST.AST,
): Either.Either<number, ParseResult.ParseIssue> {
	return ParseResult.try({
		try: () => dataView.getUint32(offset, false),
		catch(cause) {
			return new ParseResult.Type(
				ast,
				dataView,
				isError(cause) ? cause.message : "Malformed input",
			);
		},
	});
}
