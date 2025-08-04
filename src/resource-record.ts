import { Effect, Either, ParseResult, Schema, Struct } from "effect";
import { Name, decodeNameFromDnsPacketCursor } from "./name";
import { DnsPacketCursor, Uint16, Uint31, isUint31 } from "./types";
import { getUint16, getUint32 } from "./utils";

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

export const ResourceRecordTypeInteger = Schema.Literal(
	1,
	2,
	3,
	4,
	5,
	6,
	7,
	8,
	9,
	10,
	11,
	12,
	13,
	14,
	15,
	16,
).annotations({
	identifier: "Type",
	description: "Todo",
});

/**
 * 3.2.2. TYPE values
 *
 * TYPE fields are used in resource records. Note that these types are a
 * subset of QTYPEs.
 *
 * @see https://www.rfc-editor.org/rfc/rfc1035.html#section-3.2.2
 */
const ResourceRecordType = Schema.transformOrFail(
	Uint16,
	ResourceRecordTypeName,
	{
		strict: true,
		decode(uint16, _, ast) {
			switch (uint16) {
				case 1: {
					return ParseResult.succeed("A" as const);
				}
				case 2: {
					return ParseResult.succeed("NS" as const);
				}
				case 3: {
					return ParseResult.succeed("MD" as const);
				}
				case 4: {
					return ParseResult.succeed("MF" as const);
				}
				case 5: {
					return ParseResult.succeed("CNAME" as const);
				}
				case 6: {
					return ParseResult.succeed("SOA" as const);
				}
				case 7: {
					return ParseResult.succeed("MB" as const);
				}
				case 8: {
					return ParseResult.succeed("MG" as const);
				}
				case 9: {
					return ParseResult.succeed("MR" as const);
				}
				case 10: {
					return ParseResult.succeed("NULL" as const);
				}
				case 11: {
					return ParseResult.succeed("WKS" as const);
				}
				case 12: {
					return ParseResult.succeed("PTR" as const);
				}
				case 13: {
					return ParseResult.succeed("HINFO" as const);
				}
				case 14: {
					return ParseResult.succeed("MINFO" as const);
				}
				case 15: {
					return ParseResult.succeed("MX" as const);
				}
				case 16: {
					return ParseResult.succeed("TXT" as const);
				}
			}

			return ParseResult.fail(
				new ParseResult.Type(
					ast,
					uint16,
					`Type must be a integer between the values of 1 and 16. Recieved '${uint16}'`,
				),
			);
		},
		encode(rtype) {
			switch (rtype) {
				case "A": {
					return ParseResult.succeed(1 as const);
				}
				case "NS": {
					return ParseResult.succeed(2 as const);
				}
				case "MD": {
					return ParseResult.succeed(3 as const);
				}
				case "MF": {
					return ParseResult.succeed(4 as const);
				}
				case "CNAME": {
					return ParseResult.succeed(5 as const);
				}
				case "SOA": {
					return ParseResult.succeed(6 as const);
				}
				case "MB": {
					return ParseResult.succeed(7 as const);
				}
				case "MG": {
					return ParseResult.succeed(8 as const);
				}
				case "MR": {
					return ParseResult.succeed(9 as const);
				}
				case "NULL": {
					return ParseResult.succeed(10 as const);
				}
				case "WKS": {
					return ParseResult.succeed(11 as const);
				}
				case "PTR": {
					return ParseResult.succeed(12 as const);
				}
				case "HINFO": {
					return ParseResult.succeed(13 as const);
				}
				case "MINFO": {
					return ParseResult.succeed(14 as const);
				}
				case "MX": {
					return ParseResult.succeed(15 as const);
				}
				case "TXT": {
					return ParseResult.succeed(16 as const);
				}
			}
		},
	},
).annotations({
	identifier: "Type",
	description:
		"TYPE fields are used in resource records. Note that these types are a subset of QTYPEs.",
});

export type ResourceRecordType = typeof ResourceRecordType.Type;

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

export const RRTypeToRRTypeName = {
	1: "A",
	2: "NS",
	3: "MD",
	4: "MF",
	5: "CNAME",
	6: "SOA",
	7: "MB",
	8: "MG",
	9: "MR",
	10: "NULL",
	11: "WKS",
	12: "PTR",
	13: "HINFO",
	14: "MINFO",
	15: "MX",
	16: "TXT",
} as const;

const ResourceRecordClassName = Schema.Literal(
	"IN",
	"CS",
	"CH",
	"HS",
).annotations({
	identifier: "Class",
	description:
		"CLASS fields appear in resource records. The following CLASS " +
		"mnemonics",
});

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
export const ResourceRecordClass = Schema.transformOrFail(
	Uint16,
	ResourceRecordClassName,
	{
		strict: true,
		decode(uint16, _, ast) {
			switch (uint16) {
				case 1: {
					return ParseResult.succeed("IN" as const);
				}
				case 2: {
					return ParseResult.succeed("CS" as const);
				}
				case 3: {
					return ParseResult.succeed("CH" as const);
				}
				case 4: {
					return ParseResult.succeed("HS" as const);
				}
			}

			return ParseResult.fail(
				new ParseResult.Type(
					ast,
					uint16,
					`Type must be a integer between the values of 1 and 16. Recieved '${uint16}'`,
				),
			);
		},
		encode(name) {
			switch (name) {
				case "IN": {
					return ParseResult.succeed(1 as const);
				}
				case "CS": {
					return ParseResult.succeed(2 as const);
				}
				case "CH": {
					return ParseResult.succeed(3 as const);
				}
				case "HS": {
					return ParseResult.succeed(4 as const);
				}
			}
		},
	},
);

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
	type: ResourceRecordType,
	class: ResourceRecordClass,
	ttl: Uint31,
	rdlength: Uint16,
	rdata: Schema.Uint8ArrayFromSelf,
});

export type ResourceRecord = typeof ResourceRecord.Type;
export type EncodedResourceRecord = typeof ResourceRecord.Encoded;

const ResourceRecordWithEncodedByteLengthFromDnsPacketCursor =
	Schema.transformOrFail(
		DnsPacketCursor.schema,
		Schema.Struct({
			resourceRecord: Schema.encodedSchema(ResourceRecord),
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

					let offset = name.encodedByteLength;

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

					const resourceRecord = {
						name,
						type,
						class: resourceClass,
						ttl,
						rdlength,
						rdata,
					};

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
	).annotations({
		identifier: "ResourceRecord",
		description:
			"The answer, authority, and additional sections each contain a variable number of resource records. " +
			"The exact count of these records is indicated by the respective count fields in the DNS message header. " +
			"Each resource record follows a standardized format to convey information such as domain names, record types, TTL, and associated data.",
	});

export const decodeResourceRecordFromDnsPacketCursor = Schema.decode(
	ResourceRecordWithEncodedByteLengthFromDnsPacketCursor,
);

// RR types with domain names that may be compressed:
// - CNAME - Contains a domain name (CNAME field)
// - MB - Contains a domain name (MADNAME field)
// - MD (Obsolete) - Contains a domain name (MADNAME field)
// - MF (Obsolete) - Contains a domain name (MADNAME field)
// - MG - Contains a domain name (MGMNAME field)
// - MINFO - Contains two domain names (RMAILBX and EMAILBX fields)
// - MR - Contains a domain name (NEWNAME field)
// - MX - Contains a domain name (EXCHANGE field)
// - NS - Contains a domain name (NSDNAME field)
// - PTR - Contains a domain name (PTRDNAME field)
// - SOA - Contains two domain names (MNAME and RNAME fields)

// function decodeCNameRData(rdata: Uint8Array) {
//
// }
