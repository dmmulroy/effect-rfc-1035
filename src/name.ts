import {
	Effect,
	Either,
	ParseResult,
	Predicate,
	Schema,
	SchemaAST,
} from "effect";
import type { Mutable } from "effect/Types";
import { getUint16, getUint8 } from "./utils";
import { DnsPacketCursor } from "./types";

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

const Digit = Schema.Number.pipe(
	Schema.between(48, 57),
	Schema.annotations({
		identifier: "Digit",
		description: "A single digit between 0 and 9",
	}),
);

const UppercaseAsciiAlphabet = Schema.Number.pipe(
	Schema.between(65, 90),
	Schema.annotations({
		identifier: "UppercaseAsciiAlphabet",
		description: "Valid ASCII code for uppercase english letters",
	}),
);

const LowercaseAsciiAlphabet = Schema.Number.pipe(
	Schema.between(97, 122),
	Schema.annotations({
		identifier: "LowercaseAsciiAlphabet",
		description: "Valid ASCII code for lowercase english letters",
	}),
);

class AsciiHyphen extends Schema.Literal(45).annotations({
	identifier: "AsciiHyphen",
	description: "Valid ASCII code for hypen (-)",
}) {}

const isHypen = (value: unknown) => Schema.is(AsciiHyphen)(value);

class LabelCharacter extends Schema.Union(
	Digit,
	UppercaseAsciiAlphabet,
	LowercaseAsciiAlphabet,
	AsciiHyphen,
).annotations({
	identifier: "LabelCharacter",
	description: "Valid Label characters",
}) {}

const isValidLabelCharacter = (value: unknown): value is LabelCharacter =>
	Schema.is(LabelCharacter)(value);

/** Label */
export type Label = typeof Label.Type;
export type EncodedLabel = typeof Label.Encoded;

const Label = Schema.transformOrFail(Schema.Uint8ArrayFromSelf, Schema.String, {
	strict: true,
	decode(uint8Array, _, ast) {
		if (uint8Array.byteLength === 0 || uint8Array.byteLength > 63) {
			return ParseResult.fail(
				new ParseResult.Type(
					ast,
					uint8Array,
					"Label must be between 1 and 63 bytes",
				),
			);
		}

		for (let idx = 0; idx < uint8Array.byteLength; idx++) {
			const byte = uint8Array.at(idx);
			const previousByte = idx > 0 ? uint8Array.at(idx - 1) : undefined;

			if (!isValidLabelCharacter(byte)) {
				return ParseResult.fail(
					new ParseResult.Type(
						ast,
						uint8Array,
						`Invalid Label character. Labels must contain only ASCII letters (A-Z, a-z), digits (0-9), and hyphens (-). Found invalid character '${byte}'.`,
					),
				);
			}

			if (idx === 0 && isHypen(byte)) {
				return ParseResult.fail(
					new ParseResult.Type(
						ast,
						uint8Array,
						"Label can not start with hypen (-)",
					),
				);
			}

			if (idx === uint8Array.length - 1 && isHypen(byte)) {
				return ParseResult.fail(
					new ParseResult.Type(
						ast,
						uint8Array,
						"Label can not end with hypen (-)",
					),
				);
			}

			/*
			 * RFC 5891: Internationalized Domain Names in Applications (IDNA): Protocol
			 * 4.2.3.1.  Hyphen Restrictions
			 * The Unicode string MUST NOT contain "--" (two consecutive hyphens) in
			 * the third and fourth character positions and MUST NOT start or end
			 * with a "-" (hyphen).
			 *
			 * @see https://www.rfc-editor.org/rfc/rfc5891.html#section-4.2.3.1
			 */
			if (isHypen(previousByte) && isHypen(byte) && idx === 3) {
				const firstByte = uint8Array.at(0) ?? 0;
				const secondByte = uint8Array.at(1) ?? 0;

				// 120 is the 'x' ascii code. 110 is the 'n' ascii code.
				const isInternationalDomain = firstByte === 120 && secondByte === 110;
				if (!isInternationalDomain) {
					return ParseResult.fail(
						new ParseResult.Type(
							ast,
							uint8Array,
							"For non-Internationalized domain labels, the third and fourth " +
								"characters cannot be two consecutive hyphens (-).",
						),
					);
				}
			}
		}

		const decodeResult = decodeUint8ArrayToString(uint8Array, ast);

		if (Either.isLeft(decodeResult)) {
			return ParseResult.fail(decodeResult.left);
		}

		return ParseResult.succeed(decodeResult.right);
	},
	encode(str, _, ast) {
		const encodeResult = encodeStringToUint8Array(str, ast);

		if (Either.isLeft(encodeResult)) {
			return ParseResult.fail(encodeResult.left);
		}

		return ParseResult.succeed(encodeResult.right);
	},
}).annotations({
	identifier: "Label",
	description:
		"63 octets or less and only ASCII letters (A-Z, a-z), digits (0-9), and hyphens (-)",
});

export type Name = typeof Name.Type;

export const Name = Schema.Struct({
	labels: Schema.Array(Label).pipe(
		Schema.filter((labels) => {
			const textEncoder = new TextEncoder();

			let bytes = labels.length;

			for (let idx = 0; idx < labels.length; idx++) {
				const label = labels[idx] ?? "";
				bytes += textEncoder.encode(label).byteLength;
			}

			// ++bytes for null terminator byte
			if (++bytes > 255) {
				return `Name must be between 0 and 255 bytes, recieved '${bytes}'`;
			}
			return undefined;
		}),
	),
	encodedByteLength: Schema.Number.pipe(Schema.between(1, 255)),
}).annotations({ identifier: "Name", description: "255 octets or less" });

// Keep for Encoding
// export const NameFromUint8Array = Schema.transformOrFail(
// 	Schema.Uint8ArrayFromSelf,
// 	Name,
// 	{
// 		strict: true,
// 		decode(uint8Array, _, ast) {
// 			return Effect.gen(function* () {
// 				if (uint8Array.length < 2) {
// 					return yield* ParseResult.fail(
// 						new ParseResult.Type(
// 							ast,
// 							uint8Array,
// 							`NAME length must be at least 2 bytes or more, received ${uint8Array.byteLength}`,
// 						),
// 					);
// 				}
//
// 				const dataView = new DataView(
// 					uint8Array.buffer,
// 					uint8Array.byteOffset,
// 					uint8Array.byteLength,
// 				);
//
// 				let labels: Mutable<EncodedLabel>[] = [];
// 				let offset = 0;
// 				let nameSize = 0;
//
// 				while (true) {
// 					const lengthResult = getUint8(dataView, offset, ast);
//
// 					if (Either.isLeft(lengthResult)) {
// 						return yield* ParseResult.fail(lengthResult.left);
// 					}
// 					const length = lengthResult.right;
//
// 					// null terminating byte
// 					if (length === 0) {
// 						break;
// 					}
//
// 					if (offset + 1 + length > uint8Array.length) {
// 						return yield* ParseResult.fail(
// 							new ParseResult.Type(
// 								ast,
// 								uint8Array,
// 								`NAME label overruns buffer at offset ${offset}`,
// 							),
// 						);
// 					}
//
// 					const label = uint8Array.subarray(offset + 1, offset + 1 + length);
// 					nameSize += label.length;
//
// 					if (nameSize > 255) {
// 						return yield* ParseResult.fail(
// 							new ParseResult.Type(
// 								ast,
// 								uint8Array,
// 								`NAME exceeded maximum size of 255 bytes`,
// 							),
// 						);
// 					}
// 					labels.push(label);
// 					offset += length + 1;
// 				}
//
// 				return {
// 					labels,
// 					encodedByteLength: offset,
// 				};
// 			});
// 		},
// 		encode(name, _, ast) {
// 			return Effect.gen(function* () {
// 				if (name.labels.length === 0) {
// 					return yield* ParseResult.fail(
// 						new ParseResult.Type(
// 							ast,
// 							name,
// 							`NAME length must be at least 1 byte or more, received ${name.labels.length}`,
// 						),
// 					);
// 				}
// 				// length bytes + terminator byte
// 				let nameSize = name.labels.length + 1;
//
// 				for (let idx = 0; idx < name.labels.length; idx++) {
// 					const label = yield* encodeLabelFromUnknown(name.labels[idx]).pipe(
// 						Effect.mapError(Struct.get("issue")),
// 					);
//
// 					nameSize += label.byteLength;
//
// 					if (nameSize > 255) {
// 						return yield* ParseResult.fail(
// 							new ParseResult.Type(
// 								ast,
// 								name,
// 								`NAME length must be 255 bytes or less, received ${name.labels.length}`,
// 							),
// 						);
// 					}
// 				}
//
// 				const buffer = new ArrayBuffer(nameSize);
// 				const out = new Uint8Array(buffer);
// 				const dataView = new DataView(out.buffer);
//
// 				let writeOffset = 0;
//
// 				for (const label of name.labels) {
// 					yield* setUint8(dataView, writeOffset++, label.length, ast);
// 					yield* uint8ArraySet(out, label, writeOffset, ast);
// 					writeOffset += label.length;
// 				}
//
// 				// terminating zero for QNAME
// 				yield* setUint8(dataView, writeOffset++, 0x00, ast);
//
// 				return out;
// 			});
// 		},
// 	},
// ).annotations({
// 	identifier: "Name",
// 	description: "255 octets or less",
// });

// export const decodeNameFromUint8Array = Schema.decode(NameFromUint8Array);
// export const encodeNameFromUint8Array = Schema.encode(NameFromUint8Array);

const MAX_NAME_BYTE_LENGTH = 255;

type T = typeof Name.Type;
//   ^?

type E = typeof Name.Encoded;
//   ^?

const EncodedNameFromDnsPacketCursor = Schema.transformOrFail(
	DnsPacketCursor.schema,
	Schema.encodedSchema(Name),
	{
		strict: true,
		decode(cursor, _, ast) {
			return Effect.gen(function* () {
				const uint8Array = cursor.uint8Array.subarray(
					cursor.offset,
					cursor.offset + MAX_NAME_BYTE_LENGTH,
				);

				if (uint8Array.length < 2) {
					return yield* ParseResult.fail(
						new ParseResult.Type(
							ast,
							uint8Array,
							`NAME length must be at least 2 bytes or more, received ${uint8Array.byteLength}`,
						),
					);
				}

				let dataView = new DataView(
					uint8Array.buffer,
					uint8Array.byteOffset,
					uint8Array.byteLength,
				);

				let labels: Mutable<EncodedLabel>[] = [];
				let offset = 0;
				let bytesConsumed = 0;
				let nameSize = 0;
				let encounteredPointer = false;

				while (true) {
					const byteResult = getUint8(dataView, offset, ast);

					if (Either.isLeft(byteResult)) {
						return yield* ParseResult.fail(byteResult.left);
					}

					const byte = byteResult.right;

					const isPointer = byteIsPointer(byte);

					if (isPointer) {
						if (encounteredPointer === true) {
							return yield* ParseResult.fail(
								new ParseResult.Type(
									ast,
									uint8Array,
									`Encountered recursive pointer during NAME decompression`,
								),
							);
						}

						encounteredPointer = true;

						const pointerAndOffsetResult = getUint16(dataView, offset, ast);

						if (Either.isLeft(pointerAndOffsetResult)) {
							return yield* ParseResult.fail(pointerAndOffsetResult.left);
						}

						offset = getPointerOffset(pointerAndOffsetResult.right);

						// Increment bytes consumed by the pointer + offset 16 bits (e.g. 2 bytes)
						bytesConsumed += 2;

						// update the dataview to look further back in memory/the packet
						dataView = new DataView(
							cursor.uint8Array.buffer,
							cursor.uint8Array.byteOffset,
							cursor.uint8Array.byteLength,
						);
						continue;
					}

					const length = byteResult.right;

					// null terminating byte
					if (length === 0) {
						if (encounteredPointer === false) {
							bytesConsumed++;
						}
						break;
					}

					if (offset + 1 + length > dataView.byteLength) {
						return yield* ParseResult.fail(
							new ParseResult.Type(
								ast,
								uint8Array,
								`NAME label overruns buffer at offset ${offset}`,
							),
						);
					}

					const buffer = encounteredPointer ? cursor.uint8Array : uint8Array;

					const label = buffer.subarray(offset + 1, offset + 1 + length);

					nameSize += label.byteLength;

					if (nameSize > 255) {
						return yield* ParseResult.fail(
							new ParseResult.Type(
								ast,
								uint8Array,
								`NAME exceeded maximum size of 255 bytes`,
							),
						);
					}

					labels.push(label);
					offset += length + 1;

					if (encounteredPointer === false) {
						bytesConsumed = offset;
					}
				}

				return {
					labels,
					encodedByteLength: bytesConsumed,
				};
			});
		},
		encode(name, _, ast) {
			return ParseResult.fail(
				new ParseResult.Type(ast, name, "encoding is not supported"),
			);
		},
	},
);

export const decodeNameFromDnsPacketCursor = Schema.decode(
	EncodedNameFromDnsPacketCursor,
);

function byteIsPointer(byte: number) {
	return (byte & 0xc0) === 0xc0;
}

function getPointerOffset(uint16: number) {
	return uint16 & 0x3fff;
}

function decodeUint8ArrayToString(uint8Array: Uint8Array, ast: SchemaAST.AST) {
	const textDecoder = new TextDecoder("utf-8", { fatal: true });
	return ParseResult.try({
		try: () => textDecoder.decode(uint8Array),
		catch(cause) {
			return new ParseResult.Type(
				ast,
				uint8Array,
				Predicate.isError(cause) ? cause.message : "Malformed input",
			);
		},
	});
}

function encodeStringToUint8Array(str: string, ast: SchemaAST.AST) {
	const textEncoder = new TextEncoder("utf-8", { fatal: true });
	return ParseResult.try({
		try: () => textEncoder.encode(str),
		catch(cause) {
			return new ParseResult.Type(
				ast,
				str,
				Predicate.isError(cause) ? cause.message : "Malformed input",
			);
		},
	});
}
