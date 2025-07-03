import { Effect, ParseResult, Schema, Struct } from "effect";
import { decodeHeader, Header, HeaderFromUint8Array } from "./header";
import { decodeQuestion, Question, QuestionFromUint8Array } from "./question";
import {
	decodeResourceRecord,
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
	question: Schema.Array(Question),
	answer: Schema.Array(ResourceRecord),
	authority: Schema.Array(ResourceRecord),
	additional: Schema.Array(ResourceRecord),
});

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
					questions.push(question);

					// 4 bytes for qtype, qclass
					offset += question.qname.encodedByteLength + 4;
				}

				// --- Answers ---
				let answers: ResourceRecord[] = [];

				for (let idx = 0; idx < header.ancount; idx++) {
					const answerUint8Array = uint8Array.subarray(
						offset,
						offset + MAX_QUESTION_BYTE_LENGTH,
					);
					const answer = yield* decodeResourceRecord(answerUint8Array);
					answers.push(answer);

					// 4 bytes for qtype, qclass
					offset += answer.name.encodedByteLength + 10 + answer.rdlength;
				}

				// --- Nameserver Answers ---
				let authorityRecords: ResourceRecord[] = [];

				for (let idx = 0; idx < header.nscount; idx++) {
					const authorityRecordUint8Array = uint8Array.subarray(
						offset,
						offset + MAX_QUESTION_BYTE_LENGTH,
					);
					const authorityRecord = yield* decodeResourceRecord(
						authorityRecordUint8Array,
					);
					authorityRecords.push(authorityRecord);

					// 4 bytes for qtype, qclass
					offset +=
						authorityRecord.name.encodedByteLength +
						10 +
						authorityRecord.rdlength;
				}

				// --- Additional ---
				let additionalRecords: ResourceRecord[] = [];

				for (let idx = 0; idx < header.arcount; idx++) {
					const additionalRecordUint8Array = uint8Array.subarray(
						offset,
						offset + MAX_QUESTION_BYTE_LENGTH,
					);
					const additionalRecord = yield* decodeResourceRecord(
						additionalRecordUint8Array,
					);
					additionalRecords.push(additionalRecord);

					// 4 bytes for qtype, qclass
					offset +=
						additionalRecord.name.encodedByteLength +
						10 +
						additionalRecord.rdlength;
				}

				return {
					header,
					question: questions,
					answer: answers,
					authority: authorityRecords,
					additional: additionalRecords,
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
