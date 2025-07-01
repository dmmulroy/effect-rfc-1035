import { describe, expect, it } from "@effect/vitest";
import { Effect, Exit } from "effect";
import { decodeQuestion, encodeQuestion } from "../src/question";
import { arbitraryValidDnsQuestionUint8Array } from "./arbitraries";
import { RRTypeNameToRRType } from "../src";

describe("question", () => {
	it.effect.prop(
		"successfully decodes valid RFC-compliant questions",
		[arbitraryValidDnsQuestionUint8Array],
		([uint8Array]) =>
			Effect.gen(function* () {
				const result = yield* Effect.exit(decodeQuestion(uint8Array));
				if (Exit.isFailure(result)) {
					console.log(JSON.stringify(result));
				}
				expect(Exit.isSuccess(result)).toBe(true);

				if (Exit.isSuccess(result)) {
					const question = result.value;
					// Validate RFC compliance
					for (const label of question.qname.labels) {
						expect(label.length).toBeLessThanOrEqual(63);
						// Should validate label content (letters, digits, hyphens only)
					}
				}
			}),
	);

	it.effect("fails on labels with invalid characters", () =>
		Effect.gen(function* () {
			// RFC 1035: DNS labels must contain only letters, digits, and hyphens
			const invalidLabels = [
				"hello world", // space
				"test@domain", // @ symbol
				"under_score", // underscore
				"café", // non-ASCII
				"-invalid", // starts with hyphen
				"invalid-", // ends with hyphen
				"", // empty label
			];

			for (const invalidLabel of invalidLabels) {
				const labelBytes = new Uint8Array(
					Array.from(invalidLabel, (c) => c.charCodeAt(0)),
				);
				const questionBytes = new Uint8Array(invalidLabel.length + 6);

				questionBytes[0] = labelBytes.length;
				questionBytes.set(labelBytes, 1);
				questionBytes[invalidLabel.length + 1] = 0; // terminator
				// Add QTYPE and QCLASS
				questionBytes[invalidLabel.length + 2] = 0;
				questionBytes[invalidLabel.length + 3] = 1;
				questionBytes[invalidLabel.length + 4] = 0;
				questionBytes[invalidLabel.length + 5] = 1;

				const result = yield* Effect.exit(decodeQuestion(questionBytes));
				expect(Exit.isFailure(result)).toBe(true);
			}
		}),
	);

	it.effect(
		"fails on consecutive hyphens in labels when the domain is not an internationalized domain",
		() =>
			Effect.gen(function* () {
				const invalidLabel = "aa--foobar";
				const labelBytes = new Uint8Array(
					Array.from(invalidLabel, (c) => c.charCodeAt(0)),
				);
				const questionBytes = new Uint8Array(invalidLabel.length + 6);

				questionBytes[0] = labelBytes.length;
				questionBytes.set(labelBytes, 1);
				questionBytes[invalidLabel.length + 1] = 0;
				// Add QTYPE and QCLASS
				questionBytes[invalidLabel.length + 2] = 0;
				questionBytes[invalidLabel.length + 3] = 1;
				questionBytes[invalidLabel.length + 4] = 0;
				questionBytes[invalidLabel.length + 5] = 1;

				const result = yield* Effect.exit(decodeQuestion(questionBytes));
				expect(Exit.isFailure(result)).toBe(true);
			}),
	);

	it.effect("validates special/reserved domain names", () =>
		Effect.gen(function* () {
			// Test reserved domain names that should be handled specially
			const reservedDomains = [
				["localhost"],
				["example", "com"], // RFC 2606 reserved
				["test", "invalid"], // RFC 6761 special-use
			];

			for (const domain of reservedDomains) {
				const question = {
					qname: {
						labels: domain.map(
							(label) =>
								new Uint8Array(Array.from(label, (c) => c.charCodeAt(0))),
						),

						encodedByteLength: domain.reduce((sum, label) => sum + label.length + 1, 0) + 1,
					},
					qtype: RRTypeNameToRRType.A,
					qclass: 1,
				} as const;

				const encoded = yield* encodeQuestion(question);
				const decoded = yield* decodeQuestion(encoded);
				expect(decoded.qname.labels.length).toBe(domain.length);
			}
		}),
	);

	it.effect("validates QTYPE/QCLASS combinations", () =>
		Effect.gen(function* () {
			// RFC 1035: QTYPE 0 and QCLASS 0 are invalid
			const invalidCombinations = [
				{ qtype: 0, qclass: 1 }, // Invalid QTYPE 0
				{ qtype: RRTypeNameToRRType.A, qclass: 0 }, // Invalid QCLASS 0
			] as const;

			for (const combo of invalidCombinations) {
				const question = {
					qname: { labels: [new Uint8Array([116, 101, 115, 116])], encodedByteLength: 6 }, // "test" - 4 bytes + 1 length prefix + 1 terminator
					qtype: combo.qtype,
					qclass: combo.qclass,
				};

				// @ts-expect-error -- testing invalid case
				const result = yield* Effect.exit(encodeQuestion(question));
				expect(Exit.isFailure(result)).toBe(true);
			}
		}),
	);

	it.effect.prop(
		"roundtrip encoding preserves valid questions",
		[arbitraryValidDnsQuestionUint8Array],
		([uint8Array]) =>
			Effect.gen(function* () {
				const decoded = yield* decodeQuestion(uint8Array);
				const encoded = yield* encodeQuestion(decoded);
				expect(Array.from(encoded)).toEqual(Array.from(uint8Array));
			}),
	);

	it.effect("handles internationalized domain names", () =>
		Effect.gen(function* () {
			// punycode for "中.com"
			const question = {
				qname: {
					labels: [
						new Uint8Array(Array.from("xn--fsq", (c) => c.charCodeAt(0))),
						new Uint8Array(Array.from("com", (c) => c.charCodeAt(0))),
					],
					encodedByteLength: 13, // "xn--fsq" (7) + "com" (3) + 2 length prefixes + 1 terminator = 7+1+3+1+1 = 13
				},
				qtype: RRTypeNameToRRType.A,
				qclass: 1,
			} as const;

			const encoded = yield* encodeQuestion(question);
			const decoded = yield* decodeQuestion(encoded);
			expect(decoded.qname.labels.length).toBe(2);
		}),
	);

	describe("boundary conditions and edge cases", () => {
		it.effect("handles maximum label size (63 bytes) in Question context", () =>
			Effect.gen(function* () {
				// Create a label with exactly 63 bytes
				const maxLabel = new Uint8Array(63).fill(65); // 63 'A's
				const question = {
					qname: { labels: [maxLabel], encodedByteLength: 65 }, // 63 bytes + 1 length prefix + 1 terminator
					qtype: RRTypeNameToRRType.A,
					qclass: 1,
				} as const;

				const encoded = yield* encodeQuestion(question);
				const decoded = yield* decodeQuestion(encoded);
				expect(decoded.qname.labels[0]?.length).toBe(63);
			}),
		);

		it.effect("validates Name usage in Question context", () =>
			Effect.gen(function* () {
				// Valid Name should work in Question
				const validName = {
					labels: [
						new Uint8Array([119, 119, 119]), // "www"
						new Uint8Array([101, 120, 97, 109, 112, 108, 101]), // "example"
						new Uint8Array([99, 111, 109]), // "com"
					],
					encodedByteLength: 17, // "www" (3) + "example" (7) + "com" (3) + 3 length prefixes + 1 terminator = 3+1+7+1+3+1+1 = 17
				};

				const question = {
					qname: validName,
					qtype: RRTypeNameToRRType.A,
					qclass: 1,
				} as const;

				const encoded = yield* encodeQuestion(question);
				const decoded = yield* decodeQuestion(encoded);
				expect(decoded.qname.labels.length).toBe(3);

				// Invalid Name should fail in Question
				const invalidName = {
					labels: [
						new Uint8Array([45, 119, 119, 119]), // "-www" (starts with hyphen)
						new Uint8Array([101, 120, 97, 109, 112, 108, 101]), // "example"
						new Uint8Array([99, 111, 109]), // "com"
					],
					encodedByteLength: 18, // "-www" (4) + "example" (7) + "com" (3) + 3 length prefixes + 1 terminator = 4+1+7+1+3+1+1 = 18
				};

				const invalidQuestion = {
					qname: invalidName,
					qtype: RRTypeNameToRRType.A,
					qclass: 1,
				} as const;

				const result = yield* Effect.exit(encodeQuestion(invalidQuestion));
				expect(Exit.isFailure(result)).toBe(true);
			}),
		);
	});
});
