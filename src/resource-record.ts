import { Effect, Either, ParseResult, Schema, Struct } from "effect";
import {
	Name,
	decodeNameFromDnsPacketCursor,
	decodeNameFromUint8Array,
} from "./name";
import { DnsPacketCursor, Uint16, Uint31, isUint31 } from "./types";
import { getUint16, getUint32 } from "./utils";

/**
 * 3.2.2. TYPE values
 *
 * TYPE fields are used in resource records. Note that these types are a
 * subset of QTYPEs.
 *
 * @see https://www.rfc-editor.org/rfc/rfc1035.html#section-3.2.2
 */
export const ResourceRecordType = Schema.Literal(
	/** A - A host address */
	1,
	/** NS - An authoritative name server */
	2,
	/** MD - A mail destination (Obsolete - use MX) */
	3,
	/** MF - A mail forwarder (Obsolete - use MX) */
	4,
	/** CNAME - The canonical name for an alias */
	5,
	/** SOA - Marks the start of a zone of authority */
	6,
	/** MB - A mailbox domain name (EXPERIMENTAL) */
	7,
	/** MG - A mail group member (EXPERIMENTAL) */
	8,
	/** MR - A mail rename domain name (EXPERIMENTAL) */
	9,
	/** NULL - A null RR (EXPERIMENTAL) */
	10,
	/** WKS - A well known service description */
	11,
	/** PTR - A domain name pointer */
	12,
	/** HINFO - Host information */
	13,
	/** MINFO - Mailbox or mail list information */
	14,
	/** MX - Mail exchange */
	15,
	/** TXT - Text strings */
	16,
).annotations({
	identifier: "Type",
	description:
		"TYPE fields are used in resource records. Note that these types are a subset of QTYPEs.",
});

export type ResourceRecordType = typeof ResourceRecordType.Type;

export const ResourceRecordTypeName = Schema.Literal(
	"A",
	"NS",
	"MD",
	"MF",
	"CNAME",
	"SOA",
	"MB",
	"MG",
	"MR",
	"NULL",
	"WKS",
	"PTR",
	"HINFO",
	"MINFO",
	"MX",
	"TXT",
);

export type ResourceRecordTypeName = typeof ResourceRecordTypeName.Type;

export const RRTypeNameToRRType = {
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

/**
 * 3.2.4. CLASS values
 *
 * CLASS fields appear in resource records. The following CLASS mnemonics
 * and values are defined:
 *
 * IN  1  the Internet
 * CS  2  the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
 * CH  3  the CHAOS class
 * HS  4  Hesiod [Dyer 87]
 *
 * @see https://www.rfc-editor.org/rfc/rfc1035.html#section-3.2.4
 */
export const ResourceRecordClass = Schema.Literal(1, 2, 3, 4).annotations({
	identifier: "Class",
	description:
		"CLASS fields appear in resource records. The following CLASS " +
		"mnemonics",
});
/**
 * 4.1.3. Resource record format
 *
 * "The answer, authority, and additional sections all share the same " +
 * "format: a variable number of resource records, where the number of " +
 * "records is specified in the corresponding count field in the header. "
 * Each resource record has the following format: " +
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
 *      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
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
export const ResourceRecord = Schema.Struct({
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
			return Effect.gen(function* () {
				const dataView = new DataView(
					uint8Array.buffer,
					uint8Array.byteOffset,
					uint8Array.byteLength,
				);

				const name = yield* decodeNameFromUint8Array(uint8Array).pipe(
					Effect.mapError(Struct.get("issue")),
				);

				// Calculate offset manually since we know the name structure
				let offset = 0;
				for (let idx = 0; idx < name.labels.length; idx++) {
					offset += 1 + (name.labels[idx]?.byteLength ?? 0);
				}
				offset++; // null terminator

				const typeResult = getUint16(dataView, offset, ast);

				if (Either.isLeft(typeResult)) {
					return yield* ParseResult.fail(typeResult.left);
				}

				const type = typeResult.right;
				offset += 2;

				const resourceClassResult = getUint16(dataView, offset, ast);

				if (Either.isLeft(resourceClassResult)) {
					return yield* ParseResult.fail(resourceClassResult.left);
				}

				const resourceClass = resourceClassResult.right;

				offset += 2;

				const ttlResult = getUint32(dataView, offset, ast);

				if (Either.isLeft(ttlResult)) {
					return yield* ParseResult.fail(ttlResult.left);
				}

				const ttl = ttlResult.right;

				offset += 4;

				if (!isUint31(ttl)) {
					return yield* ParseResult.fail(
						new ParseResult.Type(
							ast,
							ttl,
							`TTL must be a 31-bit unsigned integer, received '${ttl}'`,
						),
					);
				}

				const rdlengthResult = getUint16(dataView, offset, ast);

				if (Either.isLeft(rdlengthResult)) {
					return yield* ParseResult.fail(rdlengthResult.left);
				}

				const rdlength = rdlengthResult.right;

				offset += 2;

				if (type === RRTypeNameToRRType.A && rdlength !== 4) {
					return yield* ParseResult.fail(
						new ParseResult.Type(
							ast,
							uint8Array,
							"When a ResourceRecord's TYPE is 1, or an A Record, the RDLENGTH must be " +
								"4 bytes, representative of an IPv4 address",
						),
					);
				}

				const rdata: Uint8Array = uint8Array.subarray(
					offset,
					offset + rdlength,
				);

				if (rdata.byteLength !== rdlength) {
					return yield* ParseResult.fail(
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

				return yield* ParseResult.succeed(resourceRecord);
			});
		},
		encode(resourceRecord, _, ast) {
			/** 1 zero byte (NAME terminator) + type + class + ttl + rdlength + rdata */
			let bufferLength = 1 + 2 + 2 + 4 + 2 + resourceRecord.rdlength;

			if (resourceRecord.name.labels.length > 255) {
				return ParseResult.fail(
					new ParseResult.Type(
						ast,
						resourceRecord,
						`NAME length must be 255 bytes or less, received ${resourceRecord.name.labels.length}`,
					),
				);
			}

			if (
				resourceRecord.type === RRTypeNameToRRType.A &&
				resourceRecord.rdlength !== 4
			) {
				return ParseResult.fail(
					new ParseResult.Type(
						ast,
						resourceRecord,
						"When a ResourceRecord's TYPE is 1, or an A Record, the RDLENGTH must be " +
							"4 bytes, representative of an IPv4 address",
					),
				);
			}

			let nameSize = 0;
			for (let idx = 0; idx < resourceRecord.name.labels.length; idx++) {
				const labelLength = resourceRecord.name.labels[idx]?.length ?? 0;

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
							resourceRecord,
							`QNAME exceeded maximum size of 255 bytes`,
						),
					);
				}
			}

			const buffer = new ArrayBuffer(bufferLength);
			const out = new Uint8Array(buffer);
			const dataView = new DataView(out.buffer);

			let writeOffset = 0;

			for (const label of resourceRecord.name.labels) {
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
).annotations({
	identifier: "ResourceRecord",
	description:
		"The answer, authority, and additional sections each contain a variable number of resource records. " +
		"The exact count of these records is indicated by the respective count fields in the DNS message header. " +
		"Each resource record follows a standardized format to convey information such as domain names, record types, TTL, and associated data.",
});

export const decodeResourceRecordFromUint8Array = Schema.decode(
	ResourceRecordFromUint8Array,
);
export const encodeResourceRecord = Schema.encode(ResourceRecordFromUint8Array);

const ResourceRecordWithEncodedByteLengthFromDnsPacketCursor =
	Schema.transformOrFail(
		DnsPacketCursor.schema,
		Schema.Struct({
			resourceRecord: ResourceRecord,
			encodedByteLength: Schema.Int,
		}),
		{
			strict: true,
			decode(cursor, _, ast) {
				return Effect.gen(function* () {
					const uint8Array = cursor.uint8Array.subarray(cursor.offset);

					const dataView = new DataView(
						uint8Array.buffer,
						uint8Array.byteOffset,
						uint8Array.byteLength,
					);

					const name = yield* decodeNameFromDnsPacketCursor(cursor).pipe(
						Effect.mapError(Struct.get("issue")),
					);

					// Calculate offset manually since we know the name structure
					let offset = 0;
					for (let idx = 0; idx < name.labels.length; idx++) {
						offset += 1 + (name.labels[idx]?.byteLength ?? 0);
					}
					offset++; // null terminator

					const typeResult = getUint16(dataView, offset, ast);

					if (Either.isLeft(typeResult)) {
						return yield* ParseResult.fail(typeResult.left);
					}

					const type = typeResult.right;
					offset += 2;

					const resourceClassResult = getUint16(dataView, offset, ast);

					if (Either.isLeft(resourceClassResult)) {
						return yield* ParseResult.fail(resourceClassResult.left);
					}

					const resourceClass = resourceClassResult.right;

					offset += 2;

					const ttlResult = getUint32(dataView, offset, ast);

					if (Either.isLeft(ttlResult)) {
						return yield* ParseResult.fail(ttlResult.left);
					}

					const ttl = ttlResult.right;

					offset += 4;

					if (!isUint31(ttl)) {
						return yield* ParseResult.fail(
							new ParseResult.Type(
								ast,
								ttl,
								`TTL must be a 31-bit unsigned integer, received '${ttl}'`,
							),
						);
					}

					const rdlengthResult = getUint16(dataView, offset, ast);

					if (Either.isLeft(rdlengthResult)) {
						return yield* ParseResult.fail(rdlengthResult.left);
					}

					const rdlength = rdlengthResult.right;

					offset += 2;

					if (type === RRTypeNameToRRType.A && rdlength !== 4) {
						return yield* ParseResult.fail(
							new ParseResult.Type(
								ast,
								uint8Array,
								"When a ResourceRecord's TYPE is 1, or an A Record, the RDLENGTH must be " +
									"4 bytes, representative of an IPv4 address",
							),
						);
					}

					const rdata: Uint8Array = uint8Array.subarray(
						offset,
						offset + rdlength,
					);

					if (rdata.byteLength !== rdlength) {
						return yield* ParseResult.fail(
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

					return {
						resourceRecord,
						encodedByteLength:
							resourceRecord.name.encodedByteLength +
							10 +
							resourceRecord.rdlength,
					};
				});
			},
			encode(resourceRecord, _, ast) {
				return ParseResult.fail(
					new ParseResult.Type(
						ast,
						resourceRecord,
						"encoding is not supported",
					),
				);
			},
		},
	);

export const decodeResourceRecordFromDnsPacketCursor = Schema.decode(
	ResourceRecordWithEncodedByteLengthFromDnsPacketCursor,
);
