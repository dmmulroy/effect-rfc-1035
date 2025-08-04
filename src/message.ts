import { Effect, ParseResult, Schema, Struct } from "effect";
import { decodeHeaderFromDnsPacket, Header } from "./header";
import {
	decodeQuestionFromDnsPacketCursor,
	Question,
	type EncodedQuestion,
} from "./question";
import {
	decodeResourceRecordFromDnsPacketCursor,
	ResourceRecord,
	type EncodedResourceRecord,
} from "./resource-record";
import { DnsPacketCursor } from "./types";

export const Message = Schema.Struct({
	header: Header,
	question: Schema.Array(Question),
	answer: Schema.Array(ResourceRecord),
	authority: Schema.Array(ResourceRecord),
	additional: Schema.Array(ResourceRecord),
}).annotations({
	identifier: "Message",
	description: "A DNS Packet Message",
});

export type Message = typeof Message.Type;
export type _ = Message["answer"];

export const MessageFromUint8Array = Schema.transformOrFail(
	Schema.Uint8ArrayFromSelf,
	Message,
	{
		strict: true,
		decode(uint8Array) {
			return Effect.gen(function* () {
				const cursor = DnsPacketCursor.fromUint8Array(uint8Array);

				// --- Header ---
				const { header, bytesConsumed } =
					yield* decodeHeaderFromDnsPacket(cursor);

				cursor.offset += bytesConsumed;

				// --- Questions ---
				let questions: EncodedQuestion[] = [];

				for (let idx = 0; idx < header.qdcount; idx++) {
					const { question, encodedByteLength } =
						yield* decodeQuestionFromDnsPacketCursor(cursor);

					// TODO: qname needs be labels as uint8Arrays
					question.qname;
					questions.push(question);

					// Progress the cursor to the next question
					cursor.offset += encodedByteLength;
				}

				// --- Answers ---
				let answers: EncodedResourceRecord[] = [];

				for (let idx = 0; idx < header.ancount; idx++) {
					const { resourceRecord: answer, encodedByteLength } =
						yield* decodeResourceRecordFromDnsPacketCursor(cursor);
					answers.push(answer);

					// Progress the cursor to the next question
					cursor.offset += encodedByteLength;
				}

				// --- Nameserver Answers ---
				let authorityRecords: EncodedResourceRecord[] = [];

				for (let idx = 0; idx < header.nscount; idx++) {
					const { resourceRecord: authorityRecord, encodedByteLength } =
						yield* decodeResourceRecordFromDnsPacketCursor(cursor);
					authorityRecords.push(authorityRecord);

					// Progress the cursor to the next question
					cursor.offset += encodedByteLength;
				}

				// --- Additional ---
				let additionalRecords: EncodedResourceRecord[] = [];

				for (let idx = 0; idx < header.arcount; idx++) {
					const { resourceRecord: additionalRecord, encodedByteLength } =
						yield* decodeResourceRecordFromDnsPacketCursor(cursor);
					additionalRecords.push(additionalRecord);

					// Progress the cursor to the next question
					cursor.offset += encodedByteLength;
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
