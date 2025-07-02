import { Effect, ParseResult, Schema, Struct } from "effect";
import { decodeHeader, Header, HeaderFromUint8Array } from "./header";
import { decodeQuestion, Question, QuestionFromUint8Array } from "./question";
import {
	ResourceRecord,
	ResourceRecordFromUint8Array,
} from "./resource-record";

export type Message = Readonly<{
	header: Header;
	question: readonly Question[];
	answer: readonly ResourceRecord[];
	authority: readonly ResourceRecord[];
	additional: readonly ResourceRecord[];
}>;

export const Message = Schema.Struct({
	header: Header,
	questions: Schema.Array(Question),
	// answer: Schema.Array(ResourceRecord),
	// authority: Schema.Array(ResourceRecord),
	// additional: Schema.Array(ResourceRecord),
});

// we know the number of questions to parse e.g. header.qdcount
//
//

const MAX_QUESTION_BYTE_LENGTH = 261;
const HEADER_BYTE_LENGTH = 12;
export const MessageFromUint8Array = Schema.transformOrFail(
	Schema.Uint8ArrayFromSelf,
	Message,
	{
		strict: true,
		decode(uint8Array) {
			return Effect.gen(function* () {
				// --- Header ---
				let offset = 0;

				const headerUint8Array = uint8Array.subarray(
					offset,
					HEADER_BYTE_LENGTH,
				);
				const header = yield* decodeHeader(headerUint8Array);

				offset += HEADER_BYTE_LENGTH;

				// --- Questions ---
				let questions: Question[] = [];

				for (let idx = 0; idx < header.qdcount; idx++) {
					const questionUint8Array = uint8Array.subarray(
						offset,
						offset + MAX_QUESTION_BYTE_LENGTH,
					);
					const question = yield* decodeQuestion(questionUint8Array);

					// 4 bytes for qtype, qclass
					offset += question.qname.encodedByteLength + 4;
				}

				return {
					header,
					questions,
				};
			}).pipe(Effect.mapError(Struct.get("issue")));
		},
		encode(message, _, ast) {
			return ParseResult.fail(
				new ParseResult.Type(ast, message, "not implemented"),
			);
		},
	},
);
