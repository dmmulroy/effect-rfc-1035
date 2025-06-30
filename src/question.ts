import { Effect, Either, ParseResult, Schema, Struct } from "effect";
import { Name, decodeNameFromUint8Array } from "./labels";
import { getUint16 } from "./utils";
import { ResourceRecordClass, ResourceRecordType } from "./resource-record";

const QTypeSchema = Schema.Union(
	ResourceRecordType,
	Schema.Literal(
		/** AFXR - A request for a transfer of an entire zone */
		252,
		/** MAILB - A request for mailbox-related records (MB, MG or MR) */
		253,
		/** MAILA - A request for mail agent RRs (Obsolete - see MX) */
		254,
		/** * - A request for all records */
		255,
	),
).annotations({
	identifier: "QType",
	description:
		"QTYPE fields appear in the question part of a query.  QTYPES are a superset " +
		"of TYPEs, hence all TYPEs are valid QTYPEs.",
});

/**
 * 3.2.3. QTYPE values
 *
 * QTYPE fields appear in the question part of a query. QTYPES are a
 * superset of TYPEs, hence all TYPEs are valid QTYPEs. In addition, the
 * following QTYPEs are defined:
 *
 * AXFR   252  A request for a transfer of an entire zone
 * MAILB  253  A request for mailbox-related records (MB, MG or MR)
 * MAILA  254  A request for mail agent RRs (Obsolete - see MX)
 * *      255  A request for all records
 *
 * @see https://www.rfc-editor.org/rfc/rfc1035.html#section-3.2.3
 */
export const QType = Schema.transformOrFail(Schema.Number, QTypeSchema, {
	strict: true,
	decode(number) {
		return decodeUnknownQType(number).pipe(
			Effect.mapError(Struct.get("issue")),
		);
	},
	encode(qtype) {
		return ParseResult.succeed(qtype);
	},
}).annotations({
	identifier: "QType",
	description:
		"QTYPE fields appear in the question part of a query.  QTYPES are a superset " +
		"of TYPEs, hence all TYPEs are valid QTYPEs.",
});

const decodeUnknownQType = Schema.decodeUnknown(QTypeSchema);

export type QType = typeof QType.Type;

const decodeQTypeFromNumber = Schema.decodeUnknown(QType);
export const decodeQType = (value: number) => decodeQTypeFromNumber(value);

export const QClassSchema = Schema.Union(
	ResourceRecordClass,
	Schema.Literal(255),
).annotations({
	identifier: "QClass",
	description:
		"QCLASS fields appear in the question section of a query. QCLASS values " +
		"are a superset of CLASS values; every CLASS is a valid QCLASS",
});

const decodeUnknownQClass = Schema.decodeUnknown(QClassSchema);

/**
 * 3.2.5. QCLASS values
 *
 * QCLASS fields appear in the question section of a query. QCLASS values
 * are a superset of CLASS values; every CLASS is a valid QCLASS. In
 * addition to CLASS values, the following QCLASSes are defined:
 *
 * *  255  any class
 *
 * @see https://www.rfc-editor.org/rfc/rfc1035.html#section-3.2.5
 */
export const QClass = Schema.transformOrFail(Schema.Number, QClassSchema, {
	strict: true,
	decode(number) {
		return decodeUnknownQClass(number).pipe(
			Effect.mapError(Struct.get("issue")),
		);
	},
	encode(qtype) {
		return ParseResult.succeed(qtype);
	},
}).annotations({
	identifier: "QClass",
	description:
		"QCLASS fields appear in the question section of a query. QCLASS values " +
		"are a superset of CLASS values; every CLASS is a valid QCLASS",
});

const decodeQClassFromNumber = Schema.decodeUnknown(QClass);

export const decodeQClass = (value: number) => decodeQClassFromNumber(value);

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
	qtype: QType,

	/**
	 * A two octet code that specifies the class of the query.
	 * For example, the QCLASS field is IN for the Internet.
	 */
	qclass: QClass,
}).annotations({
	identifier: "Question",
	description:
		"The question section is used to carry the 'question' in most " +
		"queries, i.e., the parameters that define what is being asked.",
});

export type Question = typeof Question.Type;

export const QuestionFromUint8Array = Schema.transformOrFail(
	Schema.Uint8ArrayFromSelf,
	Question,
	{
		strict: true,
		decode(uint8Array, _, ast) {
			return Effect.gen(function* () {
				if (uint8Array.length < 5) {
					return yield* ParseResult.fail(
						new ParseResult.Type(
							ast,
							uint8Array,
							`Question must have a minimum length of 5 bytes, received ${uint8Array.length}`,
						),
					);
				}

				if (uint8Array.length > 260) {
					return yield* ParseResult.fail(
						new ParseResult.Type(
							ast,
							uint8Array,
							`Question must have a maximum length of 260 bytes, received ${uint8Array.length}`,
						),
					);
				}

				const qname = yield* decodeNameFromUint8Array(uint8Array).pipe(
					Effect.mapError(Struct.get("issue")),
				);

				const dataView = new DataView(
					uint8Array.buffer,
					uint8Array.byteOffset,
					uint8Array.byteLength,
				);

				const offset = uint8Array.byteLength - 4;

				const qtypeResult = Either.map(
					getUint16(dataView, offset, ast),
					decodeQType,
				);

				if (Either.isLeft(qtypeResult)) {
					return yield* ParseResult.fail(qtypeResult.left);
				}
				const qtype = yield* Effect.mapError(
					qtypeResult.right,
					Struct.get("issue"),
				);

				const qclassResult = Either.map(
					getUint16(dataView, offset + 2, ast),
					decodeQClass,
				);

				if (Either.isLeft(qclassResult)) {
					return yield* ParseResult.fail(qclassResult.left);
				}
				const qclass = yield* Effect.mapError(
					qclassResult.right,
					Struct.get("issue"),
				);

				const question = Question.make({
					qname,
					qtype,
					qclass,
				});

				return question;
			});
		},
		encode(question, _, ast) {
			/** 1 zero byte (QNAME terminator) + 4 bytes for QTYPE & QCLASS */
			const terminatorAndQFieldsLength = 5;
			let bufferLength = terminatorAndQFieldsLength;

			if (question.qname.labels.length > 255) {
				return ParseResult.fail(
					new ParseResult.Type(
						ast,
						question,
						`QNAME length must be 255 bytes or less, received ${question.qname.labels.length}`,
					),
				);
			}

			let qnameSize = 0;
			for (let idx = 0; idx < question.qname.labels.length; idx++) {
				const labelLength = question.qname.labels[idx]?.length ?? 0;

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
							question,
							`QNAME exceeded maximum size of 255 bytes`,
						),
					);
				}
			}

			const buffer = new ArrayBuffer(bufferLength);
			const out = new Uint8Array(buffer);
			const dataView = new DataView(out.buffer);

			let writeOffset = 0;

			for (const label of question.qname.labels) {
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
