import { describe, expect, it } from "@effect/vitest";
import { Effect } from "effect";
import {
	encodeQuestionToUint8Array,
	decodeQuestionFromUint8Array,
	encodeResourceRecord,
	decodeResourceRecordFromUint8Array,
	RRTypeNameToRRType,
} from "../src/index";
import { arbitraryValidName } from "./arbitraries";

describe("boundary conditions and edge cases", () => {
	it.effect.prop(
		"validates Name roundtrip consistency across contexts",
		[arbitraryValidName],
		([labels]) =>
			Effect.gen(function* () {
				const encodedByteLength =
					labels.reduce((sum, label) => sum + label.length + 1, 0) + 1;
				const nameStruct = { labels, encodedByteLength };

				// Test Name in Question context
				const question = {
					qname: nameStruct,
					qtype: RRTypeNameToRRType.A,
					qclass: 1,
				} as const;

				const questionEncoded = yield* encodeQuestionToUint8Array(question);
				const questionDecoded =
					yield* decodeQuestionFromUint8Array(questionEncoded);
				expect(questionDecoded.qname.labels.length).toEqual(labels.length);

				// Test same Name in ResourceRecord context
				const record = {
					name: nameStruct,
					type: RRTypeNameToRRType.A,
					class: 1,
					ttl: 3600,
					rdlength: 4,
					rdata: new Uint8Array([192, 0, 2, 1]),
				} as const;

				const recordEncoded = yield* encodeResourceRecord(record);
				const recordDecoded =
					yield* decodeResourceRecordFromUint8Array(recordEncoded);
				expect(recordDecoded.name.labels.length).toBe(labels.length);

				// Both contexts should preserve the same Name structure
				for (let i = 0; i < labels.length; i++) {
					expect(Array.from(questionDecoded.qname.labels[i] || [])).toEqual(
						Array.from(recordDecoded.name.labels[i] || []),
					);
				}
			}),
	);
});
