import { describe, expect, it } from "@effect/vitest";
import { Effect, Exit, Schema } from "effect";
import {
	Label,
	Name,
	decodeNameFromUint8Array,
	encodeNameFromUint8Array,
} from "../src/labels";
import {
	arbitraryValidLabel,
	arbitraryInvalidLabel,
	arbitraryValidName,
	arbitraryInvalidName,
	arbitraryValidNameUint8Array,
	arbitraryInvalidNameUint8Array,
	arbitraryValidNameStruct,
	arbitraryInvalidNameWireFormat,
} from "./arbitraries";

describe("Label", () => {
	it.effect.prop(
		"successfully validates valid RFC-compliant labels",
		[arbitraryValidLabel],
		([uint8Array]) =>
			Effect.gen(function* () {
				const result = yield* Effect.exit(
					Effect.sync(() => Schema.is(Label)(uint8Array)),
				);
				expect(result).toEqual(Exit.succeed(true));
			}),
	);

	it.effect.prop(
		"rejects invalid labels",
		[arbitraryInvalidLabel],
		([uint8Array]) =>
			Effect.gen(function* () {
				const result = yield* Effect.exit(
					Effect.sync(() => Schema.is(Label)(uint8Array)),
				);
				expect(result).toEqual(Exit.succeed(false));
			}),
	);

	it.effect("validates label length boundary (63 bytes)", () =>
		Effect.gen(function* () {
			// Exactly 63 bytes - should pass
			const maxLabel = new Uint8Array(63).fill(65); // 63 'A's
			const validResult = yield* Effect.exit(
				Effect.sync(() => Schema.is(Label)(maxLabel)),
			);
			expect(validResult).toEqual(Exit.succeed(true));

			// 64 bytes - should fail
			const tooLongLabel = new Uint8Array(64).fill(65); // 64 'A's
			const invalidResult = yield* Effect.exit(
				Effect.sync(() => Schema.is(Label)(tooLongLabel)),
			);
			expect(invalidResult).toEqual(Exit.succeed(false));
		}),
	);

	it.effect("validates character restrictions", () =>
		Effect.gen(function* () {
			// Valid characters: letters (A-Z, a-z), digits (0-9), hyphens (-)
			const validChars = [
				new Uint8Array([65]), // 'A'
				new Uint8Array([90]), // 'Z'
				new Uint8Array([97]), // 'a'
				new Uint8Array([122]), // 'z'
				new Uint8Array([48]), // '0'
				new Uint8Array([57]), // '9'
				new Uint8Array([65, 45, 65]), // 'A-A' (hyphen in middle)
				new Uint8Array([48, 45, 57]), // '0-9' (digit-hyphen-digit)
			];

			for (const label of validChars) {
				const result = yield* Effect.exit(
					Effect.sync(() => Schema.is(Label)(label)),
				);
				expect(result).toEqual(Exit.succeed(true));
			}

			// Invalid characters: everything else
			const invalidChars = [
				new Uint8Array([32]), // space
				new Uint8Array([64]), // '@'
				new Uint8Array([95]), // '_'
				new Uint8Array([46]), // '.'
				new Uint8Array([33]), // '!'
				new Uint8Array([126]), // '~'
				new Uint8Array([47]), // '/'
				new Uint8Array([58]), // ':'
			];

			for (const label of invalidChars) {
				const result = yield* Effect.exit(
					Effect.sync(() => Schema.is(Label)(label)),
				);
				expect(result).toEqual(Exit.succeed(false));
			}
		}),
	);

	it.effect("validates hyphen placement rules", () =>
		Effect.gen(function* () {
			// Cannot start with hyphen
			const startsWithHyphen = new Uint8Array([45, 65]); // '-A'
			const startResult = yield* Effect.exit(
				Effect.sync(() => Schema.is(Label)(startsWithHyphen)),
			);
			expect(startResult).toEqual(Exit.succeed(false));

			// Cannot end with hyphen
			const endsWithHyphen = new Uint8Array([65, 45]); // 'A-'
			const endResult = yield* Effect.exit(
				Effect.sync(() => Schema.is(Label)(endsWithHyphen)),
			);
			expect(endResult).toEqual(Exit.succeed(false));

			// Can have hyphen in middle
			const validHyphen = new Uint8Array([65, 45, 65]); // 'A-A'
			const validResult = yield* Effect.exit(
				Effect.sync(() => Schema.is(Label)(validHyphen)),
			);
			expect(validResult).toEqual(Exit.succeed(true));

			// Cannot have consecutive hyphens in the 3rd and 4th indicies
			const consecutiveHyphens = new Uint8Array([65, 65, 45, 45]); // 'AA--'
			const consecutiveResult = yield* Effect.exit(
				Effect.sync(() => Schema.is(Label)(consecutiveHyphens)),
			);
			expect(consecutiveResult).toEqual(Exit.succeed(false));
		}),
	);

	it.effect("validates edge cases", () =>
		Effect.gen(function* () {
			// Empty label - should fail (RFC requires 1-63 octets)
			const empty = new Uint8Array(0);
			const emptyResult = yield* Effect.exit(
				Effect.sync(() => Schema.is(Label)(empty)),
			);
			expect(emptyResult).toEqual(Exit.succeed(false));

			// Single character letter - should pass
			const singleLetter = new Uint8Array([65]); // 'A'
			const singleLetterResult = yield* Effect.exit(
				Effect.sync(() => Schema.is(Label)(singleLetter)),
			);
			expect(singleLetterResult).toEqual(Exit.succeed(true));

			// Single character digit - should pass
			const singleDigit = new Uint8Array([48]); // '0'
			const singleDigitResult = yield* Effect.exit(
				Effect.sync(() => Schema.is(Label)(singleDigit)),
			);
			expect(singleDigitResult).toEqual(Exit.succeed(true));

			// Single hyphen - should fail (cannot start with hyphen)
			const singleHyphen = new Uint8Array([45]); // '-'
			const singleHyphenResult = yield* Effect.exit(
				Effect.sync(() => Schema.is(Label)(singleHyphen)),
			);
			expect(singleHyphenResult).toEqual(Exit.succeed(false));

			// Two valid characters - should pass
			const two = new Uint8Array([65, 66]); // 'AB'
			const twoResult = yield* Effect.exit(
				Effect.sync(() => Schema.is(Label)(two)),
			);
			expect(twoResult).toEqual(Exit.succeed(true));

			// Mixed letters, digits, and valid hyphen - should pass
			const mixed = new Uint8Array([65, 48, 45, 66, 57]); // 'A0-B9'
			const mixedResult = yield* Effect.exit(
				Effect.sync(() => Schema.is(Label)(mixed)),
			);
			expect(mixedResult).toEqual(Exit.succeed(true));
		}),
	);

	it.effect.prop(
		"roundtrip validation preserves valid labels",
		[arbitraryValidLabel],
		([label]) =>
			Effect.gen(function* () {
				// Test that valid labels pass validation consistently
				const result1 = yield* Effect.exit(
					Effect.sync(() => Schema.is(Label)(label)),
				);
				expect(result1).toEqual(Exit.succeed(true));

				// Test that Schema.decodeUnknown and Schema.encodeUnknown work
				const decoded = yield* Schema.decodeUnknown(Label)(label);
				const encoded = yield* Schema.encodeUnknown(Label)(decoded);

				// Should be identical since Label is just Uint8Array with validation
				expect(Array.from(encoded)).toEqual(Array.from(label));
			}),
	);

	it.effect.prop(
		"roundtrip encoding fails for invalid labels",
		[arbitraryInvalidLabel],
		([label]) =>
			Effect.gen(function* () {
				// Invalid labels should fail decoding
				const result = yield* Effect.exit(Schema.decodeUnknown(Label)(label));
				expect(Exit.isFailure(result)).toBe(true);
			}),
	);

	it.effect("validates roundtrip edge cases for labels", () =>
		Effect.gen(function* () {
			// Test boundary cases
			const testCases = [
				new Uint8Array([65]), // Single 'A'
				new Uint8Array([48]), // Single '0'
				new Uint8Array(63).fill(65), // Max length (63 'A's)
				new Uint8Array([65, 45, 90]), // 'A-Z'
				new Uint8Array([48, 45, 57]), // '0-9'
			];

			for (const label of testCases) {
				const decoded = yield* Schema.decodeUnknown(Label)(label);
				const encoded = yield* Schema.encodeUnknown(Label)(decoded);
				expect(Array.from(encoded)).toEqual(Array.from(label));
			}
		}),
	);
});

describe("Name", () => {
	it.effect.prop(
		"successfully validates valid RFC-compliant names",
		[arbitraryValidName],
		([labels]) =>
			Effect.gen(function* () {
				const encodedByteLength =
					labels.reduce((sum, label) => sum + label.length + 1, 0) + 1;
				const nameStruct = { labels, encodedByteLength };
				const result = yield* Effect.exit(
					Effect.sync(() => Schema.is(Name)(nameStruct)),
				);
				expect(result).toEqual(Exit.succeed(true));
			}),
	);

	it.effect.prop("rejects invalid names", [arbitraryInvalidName], ([labels]) =>
		Effect.gen(function* () {
			const encodedByteLength =
				labels.reduce((sum, label) => sum + label.length + 1, 0) + 1;
			const nameStruct = { labels, encodedByteLength };
			const result = yield* Effect.exit(
				Effect.sync(() => Schema.is(Name)(nameStruct)),
			);
			expect(result).toEqual(Exit.succeed(false));
		}),
	);

	it.effect("validates name length boundary (255 octets)", () =>
		Effect.gen(function* () {
			// Create a name at exactly 255 octets total
			// Each label: 1 byte length + content
			// 4 labels of 63 bytes each = 4 * 63 = 252 bytes
			// Plus 4 length bytes + 1 terminator = 257 bytes (exceeds limit)
			// So use 3 labels of 63 bytes = 3 * 63 = 189 bytes
			// Plus 3 length bytes + 1 terminator = 193 bytes (within limit)
			const maxLabel = new Uint8Array(63).fill(65); // 63 'A's
			const validLabels = [maxLabel, maxLabel, maxLabel];
			const encodedByteLength =
				validLabels.reduce((sum, label) => sum + label.length + 1, 0) + 1;
			const validNameStruct = {
				labels: validLabels,
				encodedByteLength,
			}; // 193 total bytes

			const validResult = yield* Effect.exit(
				Effect.sync(() => Schema.is(Name)(validNameStruct)),
			);
			expect(validResult).toEqual(Exit.succeed(true));

			// Create a name exceeding 255 octets
			const oversizedLabels = [
				maxLabel,
				maxLabel,
				maxLabel,
				maxLabel,
				maxLabel,
			];
			const oversizedEncodedByteLength =
				oversizedLabels.reduce((sum, label) => sum + label.length + 1, 0) + 1;
			const oversizedNameStruct = {
				labels: oversizedLabels,
				encodedByteLength: oversizedEncodedByteLength,
			};
			const invalidResult = yield* Effect.exit(
				Effect.sync(() => Schema.is(Name)(oversizedNameStruct)),
			);
			expect(invalidResult).toEqual(Exit.succeed(false));
		}),
	);

	it.effect("validates empty name arrays", () =>
		Effect.gen(function* () {
			// Empty array should fail (RFC requires at least one label)
			const emptyLabels: Uint8Array[] = [];
			const emptyEncodedByteLength =
				emptyLabels.reduce((sum, label) => sum + label.length + 1, 0) + 1;
			const emptyNameStruct = {
				labels: emptyLabels,
				encodedByteLength: emptyEncodedByteLength,
			};
			const result = yield* Effect.exit(
				Effect.sync(() => Schema.is(Name)(emptyNameStruct)),
			);
			expect(result).toEqual(Exit.succeed(false));
		}),
	);

	it.effect.prop(
		"roundtrip validation preserves valid names",
		[arbitraryValidName],
		([labels]) =>
			Effect.gen(function* () {
				const encodedByteLength =
					labels.reduce((sum, label) => sum + label.length + 1, 0) + 1;
				const nameStruct = { labels, encodedByteLength };

				// Test that valid names pass validation consistently
				const result1 = yield* Effect.exit(
					Effect.sync(() => Schema.is(Name)(nameStruct)),
				);
				expect(result1).toEqual(Exit.succeed(true));

				// Test that Schema.decodeUnknown and Schema.encodeUnknown work
				const decoded = yield* Schema.decodeUnknown(Name)(nameStruct);
				const encoded = yield* Schema.encodeUnknown(Name)(decoded);

				// Should be identical since Name is a struct with labels and encodedByteLength
				expect(encoded.labels.length).toEqual(labels.length);
				for (let i = 0; i < labels.length; i++) {
					expect(encoded.labels[i]).toEqual(labels[i]);
				}
			}),
	);

	describe("binary encoding/decoding", () => {
		it.effect.prop(
			"decodeNameFromUint8Array successfully decodes valid wire format names",
			[arbitraryValidNameUint8Array],
			([uint8Array]) =>
				Effect.gen(function* () {
					const result = yield* Effect.exit(
						decodeNameFromUint8Array(uint8Array),
					);
					if (Exit.isFailure(result)) {
						console.log(JSON.stringify(result, null, 2));
					}

					expect(Exit.isSuccess(result)).toBe(true);

					if (Exit.isSuccess(result)) {
						const name = result.value;
						// Verify structure is valid (now a struct, not array)
						expect(typeof name).toBe("object");
						expect(name.labels).toBeDefined();
						expect(Array.isArray(name.labels)).toBe(true);
						expect(name.labels.length).toBeGreaterThan(0);

						// Verify each label is valid
						for (const label of name.labels) {
							expect(label.length).toBeLessThanOrEqual(63);
							expect(label.length).toBeGreaterThan(0);
						}
					}
				}),
		);

		it.effect.prop(
			"decodeNameFromUint8Array rejects invalid wire format names",
			[arbitraryInvalidNameUint8Array],
			([uint8Array]) =>
				Effect.gen(function* () {
					const result = yield* Effect.exit(
						decodeNameFromUint8Array(uint8Array),
					);
					expect(Exit.isFailure(result)).toBe(true);
				}),
		);

		it.effect.prop(
			"encodeNameFromUint8Array successfully encodes valid names",
			[arbitraryValidName],
			([labels]) =>
				Effect.gen(function* () {
					const encodedByteLength =
						labels.reduce((sum, label) => sum + label.length + 1, 0) + 1;
					const nameStruct = { labels, encodedByteLength };
					const result = yield* Effect.exit(
						encodeNameFromUint8Array(nameStruct),
					);
					expect(Exit.isSuccess(result)).toBe(true);

					if (Exit.isSuccess(result)) {
						const encoded = result.value;
						// Verify wire format structure
						expect(encoded.length).toBeGreaterThan(0);
						expect(encoded[encoded.length - 1]).toBe(0); // Ends with null terminator

						// Verify length prefixes are reasonable
						let offset = 0;
						for (const label of labels) {
							expect(encoded[offset]).toBe(label.length); // Length prefix matches
							offset += label.length + 1;
						}
					}
				}),
		);

		it.effect.prop(
			"encodeNameFromUint8Array rejects invalid names",
			[arbitraryInvalidName],
			([labels]) =>
				Effect.gen(function* () {
					const encodedByteLength =
						labels.reduce((sum, label) => sum + label.length + 1, 0) + 1;
					const nameStruct = { labels, encodedByteLength };
					const result = yield* Effect.exit(
						encodeNameFromUint8Array(nameStruct),
					);
					expect(Exit.isFailure(result)).toBe(true);
				}),
		);

		it.effect.prop(
			"roundtrip binary encoding preserves valid names",
			[arbitraryValidNameUint8Array],
			([uint8Array]) =>
				Effect.gen(function* () {
					const decoded = yield* decodeNameFromUint8Array(uint8Array);
					const encoded = yield* encodeNameFromUint8Array(decoded);

					// Should be identical byte arrays
					expect(encoded).toEqual(uint8Array);
				}),
		);

		it.effect("validates specific wire format cases", () =>
			Effect.gen(function* () {
				// Single label "test"
				//                                 [4, t,   e,   s,   t,   0]
				const singleLabel = new Uint8Array([4, 116, 101, 115, 116, 0]);
				const decoded1 = yield* decodeNameFromUint8Array(singleLabel);
				expect(decoded1.labels.length).toBe(1);
				expect(Array.from(decoded1.labels[0] ?? [])).toEqual([
					116, 101, 115, 116,
				]);

				// Two labels "www.example"
				const twoLabels = new Uint8Array([
					3, 119, 119, 119, 7, 101, 120, 97, 109, 112, 108, 101, 0,
				]);
				const decoded2 = yield* decodeNameFromUint8Array(twoLabels);
				expect(decoded2.labels.length).toBe(2);
				expect(Array.from(decoded2.labels[0] ?? [])).toEqual([119, 119, 119]); // "www"
				expect(Array.from(decoded2.labels[1] ?? [])).toEqual([
					101, 120, 97, 109, 112, 108, 101,
				]); // "example"

				// Empty name (just terminator)
				const emptyName = new Uint8Array([0]);
				const result = yield* Effect.exit(decodeNameFromUint8Array(emptyName));
				expect(Exit.isFailure(result)).toBe(true); // Should fail - no labels before terminator
			}),
		);

		it.effect("validates edge cases and error conditions", () =>
			Effect.gen(function* () {
				// Buffer too short
				const tooShort = new Uint8Array([5, 116]);
				const result1 = yield* Effect.exit(decodeNameFromUint8Array(tooShort));
				expect(Exit.isFailure(result1)).toBe(true);

				// Missing terminator
				const noTerminator = new Uint8Array([4, 116, 101, 115, 116]);
				const result2 = yield* Effect.exit(
					decodeNameFromUint8Array(noTerminator),
				);
				expect(Exit.isFailure(result2)).toBe(true);

				// Label too long (>63 bytes)
				const longLabel = new Uint8Array([64, ...new Array(64).fill(65), 0]);
				const result3 = yield* Effect.exit(decodeNameFromUint8Array(longLabel));
				expect(Exit.isFailure(result3)).toBe(true);

				// Total size exceeding 255 bytes
				const oversized = new Uint8Array(300);
				oversized[0] = 255; // Impossible length
				const result4 = yield* Effect.exit(decodeNameFromUint8Array(oversized));
				expect(Exit.isFailure(result4)).toBe(true);
			}),
		);

		it.effect("validates wire format encoding consistency", () =>
			Effect.gen(function* () {
				// Test specific known encodings
				const testCases = [
					{
						nameStruct: {
							labels: [new Uint8Array([65])],
							encodedByteLength: 3,
						}, // ["A"]
						expected: new Uint8Array([1, 65, 0]),
					},
					{
						nameStruct: {
							labels: [
								new Uint8Array([116, 101, 115, 116]), // "test"
								new Uint8Array([99, 111, 109]), // "com"
							],
							encodedByteLength: 10,
						},
						expected: new Uint8Array([
							4, 116, 101, 115, 116, 3, 99, 111, 109, 0,
						]),
					},
					{
						nameStruct: {
							labels: [
								new Uint8Array([65, 45, 66]), // "A-B"
								new Uint8Array([49, 50, 51]), // "123"
							],
							encodedByteLength: 9,
						},
						expected: new Uint8Array([3, 65, 45, 66, 3, 49, 50, 51, 0]),
					},
				];

				for (const testCase of testCases) {
					const encoded = yield* encodeNameFromUint8Array(testCase.nameStruct);
					expect(Array.from(encoded)).toEqual(Array.from(testCase.expected));

					// Verify roundtrip
					const decoded = yield* decodeNameFromUint8Array(encoded);
					expect(decoded.labels.length).toBe(testCase.nameStruct.labels.length);
					for (let i = 0; i < testCase.nameStruct.labels.length; i++) {
						expect(decoded.labels[i]).toEqual(testCase.nameStruct.labels[i]);
					}
				}
			}),
		);

		it.effect("validates RFC 1035 size limits in wire format", () =>
			Effect.gen(function* () {
				// Maximum valid label (63 bytes)
				const maxLabel = new Uint8Array(63).fill(65); // 63 'A's
				const maxLabelNameStruct = {
					labels: [maxLabel],
					encodedByteLength: 65,
				};
				const encoded1 = yield* encodeNameFromUint8Array(maxLabelNameStruct);
				const decoded1 = yield* decodeNameFromUint8Array(encoded1);
				expect(decoded1.labels[0]?.length).toBe(63);

				// Multiple labels approaching size limit
				const multipleLabelsStruct = {
					labels: [
						new Uint8Array(60).fill(65), // 60 'A's
						new Uint8Array(60).fill(66), // 60 'B's
						new Uint8Array(60).fill(67), // 60 'C's
						new Uint8Array(60).fill(68), // 60 'D's
					],
					encodedByteLength: 245,
				};

				// This should be within limits: 4 * (60 + 1) + 1 = 245 bytes
				const encoded2 = yield* encodeNameFromUint8Array(multipleLabelsStruct);
				const decoded2 = yield* decodeNameFromUint8Array(encoded2);
				expect(decoded2.labels.length).toBe(4);
			}),
		);
	});

	describe("boundary conditions and edge cases", () => {
		it.effect("validates maximum label size boundary (63 bytes)", () =>
			Effect.gen(function* () {
				// Exactly 63 bytes should pass
				const maxValidLabel = new Uint8Array(63).fill(65); // 63 'A's
				const validResult = yield* Effect.exit(
					Schema.decodeUnknown(Label)(maxValidLabel),
				);
				expect(Exit.isSuccess(validResult)).toBe(true);

				// 64 bytes should fail
				const oversizedLabel = new Uint8Array(64).fill(65); // 64 'A's
				const invalidResult = yield* Effect.exit(
					Schema.decodeUnknown(Label)(oversizedLabel),
				);
				expect(Exit.isFailure(invalidResult)).toBe(true);
			}),
		);

		it.effect("validates maximum name size boundary (255 bytes)", () =>
			Effect.gen(function* () {
				// Create names approaching the 255 byte wire format limit
				// RFC 1035: Names are limited to 255 octets in wire format
				const label63 = new Uint8Array(63).fill(65); // 63 'A's each

				// 3 labels = 3*63 + 3 length bytes + 1 terminator = 193 bytes (valid)
				const validNameStruct = {
					labels: [label63, label63, label63],
					encodedByteLength: 193,
				};
				const validResult = yield* Effect.exit(
					Effect.sync(() => Schema.is(Name)(validNameStruct)),
				);
				expect(validResult).toEqual(Exit.succeed(true));

				// 4 labels = 4*63 + 4 length bytes + 1 terminator = 257 bytes (invalid, exceeds 255)
				const invalidNameStruct = {
					labels: [label63, label63, label63, label63],
					encodedByteLength: 257,
				};
				const invalidResult = yield* Effect.exit(
					Effect.sync(() => Schema.is(Name)(invalidNameStruct)),
				);

				expect(invalidResult).toEqual(Exit.succeed(false));
			}),
		);

		it.effect("validates label character restrictions at boundaries", () =>
			Effect.gen(function* () {
				// Label starting with hyphen should fail
				const startsWithHyphen = new Uint8Array([45, 65, 66]); // "-AB"
				const result1 = yield* Effect.exit(
					Schema.decodeUnknown(Label)(startsWithHyphen),
				);
				expect(Exit.isFailure(result1)).toBe(true);

				// Label ending with hyphen should fail
				const endsWithHyphen = new Uint8Array([65, 66, 45]); // "AB-"
				const result2 = yield* Effect.exit(
					Schema.decodeUnknown(Label)(endsWithHyphen),
				);
				expect(Exit.isFailure(result2)).toBe(true);

				// Label with consecutive hyphens in 3rd-4th position should fail (non-IDN)
				const consecutiveHyphens = new Uint8Array([65, 65, 45, 45, 66]); // "AA--B"
				const result3 = yield* Effect.exit(
					Schema.decodeUnknown(Label)(consecutiveHyphens),
				);
				expect(Exit.isFailure(result3)).toBe(true);
			}),
		);

		it.effect("validates empty name edge case", () =>
			Effect.gen(function* () {
				// Empty labels array should fail
				const emptyNameStruct = {
					labels: [] as Uint8Array[],
					encodedByteLength: 1,
				};
				const result = yield* Effect.exit(
					Effect.sync(() => Schema.is(Name)(emptyNameStruct)),
				);
				expect(result).toEqual(Exit.succeed(false));
			}),
		);
	});
});

describe("Name struct with encodedByteLength", () => {
	it.effect.prop(
		"encodedByteLength property correctly tracks bytes consumed during decoding",
		[arbitraryValidNameStruct],
		([{ wireFormat, expectedName }]) =>
			Effect.gen(function* () {
				const decoded = yield* decodeNameFromUint8Array(wireFormat);

				// Verify the encodedByteLength matches what we calculated manually
				expect(decoded.encodedByteLength).toBe(expectedName.encodedByteLength);

				// Verify the encodedByteLength is at least the length of all labels plus their length bytes plus terminator
				const expectedMinLength =
					decoded.labels.reduce((sum, label) => sum + label.length + 1, 0) + 1;
				expect(decoded.encodedByteLength).toBeGreaterThanOrEqual(
					expectedMinLength,
				);

				// Verify the labels match
				expect(decoded.labels.length).toBe(expectedName.labels.length);
				for (let i = 0; i < decoded.labels.length; i++) {
					expect(decoded.labels[i]).toEqual(expectedName.labels[i]);
				}
			}),
	);

	it.effect.prop(
		"decoding wire format creates valid Name struct instances",
		[arbitraryValidNameUint8Array],
		([wireFormat]) =>
			Effect.gen(function* () {
				const decoded = yield* decodeNameFromUint8Array(wireFormat);

				// Verify it's a struct with the expected properties
				expect(typeof decoded).toBe("object");
				expect(decoded.labels).toBeDefined();
				expect(Array.isArray(decoded.labels)).toBe(true);
				expect(typeof decoded.encodedByteLength).toBe("number");
				expect(decoded.encodedByteLength).toBeGreaterThan(0);

				// Verify encodedByteLength doesn't exceed wire format length
				expect(decoded.encodedByteLength).toBeLessThanOrEqual(
					wireFormat.length,
				);

				// Verify each label is valid
				for (const label of decoded.labels) {
					expect(label.length).toBeGreaterThan(0);
					expect(label.length).toBeLessThanOrEqual(63);
				}
			}),
	);

	it.effect.prop(
		"decoding rejects invalid wire formats",
		[arbitraryInvalidNameWireFormat],
		([invalidWireFormat]) =>
			Effect.gen(function* () {
				const result = yield* Effect.exit(
					decodeNameFromUint8Array(invalidWireFormat),
				);
				expect(Exit.isFailure(result)).toBe(true);
			}),
	);

	it.effect("validates specific encodedByteLength calculations", () =>
		Effect.gen(function* () {
			// Test known wire format cases
			const testCases = [
				{
					name: "single label 'test'",
					wireFormat: new Uint8Array([4, 116, 101, 115, 116, 0]), // "test"
					expectedEncodedByteLength: 6,
					expectedLabels: 1,
				},
				{
					name: "two labels 'www.example'",
					wireFormat: new Uint8Array([
						3, 119, 119, 119, 7, 101, 120, 97, 109, 112, 108, 101, 0,
					]),
					expectedEncodedByteLength: 13,
					expectedLabels: 2,
				},
				{
					name: "single character label 'a'",
					wireFormat: new Uint8Array([1, 97, 0]), // "a"
					expectedEncodedByteLength: 3,
					expectedLabels: 1,
				},
				{
					name: "maximum length label (63 chars)",
					wireFormat: new Uint8Array([63, ...new Array(63).fill(65), 0]), // 63 'A's
					expectedEncodedByteLength: 65, // 1 (length) + 63 (data) + 1 (terminator)
					expectedLabels: 1,
				},
			];

			for (const testCase of testCases) {
				const decoded = yield* decodeNameFromUint8Array(testCase.wireFormat);

				expect(decoded.encodedByteLength).toBe(
					testCase.expectedEncodedByteLength,
				);
				expect(decoded.labels.length).toBe(testCase.expectedLabels);

				// Verify the encoded byte length equals the wire format length
				expect(decoded.encodedByteLength).toBe(testCase.wireFormat.length);
			}
		}),
	);

	it.effect("validates encodedByteLength with various name structures", () =>
		Effect.gen(function* () {
			// Test multiple labels with different sizes
			const multiLabel = new Uint8Array([
				2,
				65,
				66, // "AB" (3 bytes)
				5,
				67,
				68,
				69,
				70,
				71, // "CDEFG" (6 bytes)
				1,
				72, // "H" (2 bytes)
				0, // terminator (1 byte)
			]); // Total: 12 bytes

			const decoded = yield* decodeNameFromUint8Array(multiLabel);
			expect(decoded.encodedByteLength).toBe(12);
			expect(decoded.labels.length).toBe(3);

			// Verify individual labels
			expect(Array.from(decoded.labels[0] ?? [])).toEqual([65, 66]); // "AB"
			expect(Array.from(decoded.labels[1] ?? [])).toEqual([67, 68, 69, 70, 71]); // "CDEFG"
			expect(Array.from(decoded.labels[2] ?? [])).toEqual([72]); // "H"
		}),
	);

	it.effect(
		"validates encodedByteLength accuracy for roundtrip operations",
		() =>
			Effect.gen(function* () {
				// Create a known name structure
				const originalName = {
					labels: [
						new Uint8Array([116, 101, 115, 116]), // "test"
						new Uint8Array([99, 111, 109]), // "com"
					],
					encodedByteLength: 10, // Will be calculated during encoding
				};

				// Encode to wire format
				const encoded = yield* encodeNameFromUint8Array(originalName);

				// Decode back to Name struct
				const decoded = yield* decodeNameFromUint8Array(encoded);

				// Verify encodedByteLength matches the encoded wire format length
				expect(decoded.encodedByteLength).toBe(encoded.length);

				// Verify the structure is preserved
				expect(decoded.labels.length).toBe(2);
				expect(decoded.labels[0]).toEqual(originalName.labels[0]);
				expect(decoded.labels[1]).toEqual(originalName.labels[1]);
			}),
	);

	it.effect("validates error conditions and boundary cases", () =>
		Effect.gen(function* () {
			// Buffer too short (less than 2 bytes)
			const tooShort = new Uint8Array([1]);
			const result1 = yield* Effect.exit(decodeNameFromUint8Array(tooShort));
			expect(Exit.isFailure(result1)).toBe(true);

			// Empty buffer
			const empty = new Uint8Array([]);
			const result2 = yield* Effect.exit(decodeNameFromUint8Array(empty));
			expect(Exit.isFailure(result2)).toBe(true);

			// Label length exceeds buffer
			const overrun = new Uint8Array([10, 65, 66]); // Claims 10 bytes but only has 2
			const result3 = yield* Effect.exit(decodeNameFromUint8Array(overrun));
			expect(Exit.isFailure(result3)).toBe(true);

			// Missing terminator
			const noTerminator = new Uint8Array([4, 116, 101, 115, 116]); // "test" without 0
			const result4 = yield* Effect.exit(
				decodeNameFromUint8Array(noTerminator),
			);
			expect(Exit.isFailure(result4)).toBe(true);
		}),
	);

	it.effect("validates encodedByteLength with edge case sizes", () =>
		Effect.gen(function* () {
			// Minimum valid name (single 1-byte label)
			const minName = new Uint8Array([1, 65, 0]); // "A"
			const decoded1 = yield* decodeNameFromUint8Array(minName);
			expect(decoded1.encodedByteLength).toBe(3);
			expect(decoded1.labels.length).toBe(1);

			// Multiple small labels approaching size limit
			const manySmallLabels = new Uint8Array([
				1,
				65, // "A"
				1,
				66, // "B"
				1,
				67, // "C"
				1,
				68, // "D"
				1,
				69, // "E"
				0, // terminator
			]); // Total: 11 bytes

			const decoded2 = yield* decodeNameFromUint8Array(manySmallLabels);
			expect(decoded2.encodedByteLength).toBe(11);
			expect(decoded2.labels.length).toBe(5);
		}),
	);

	it.effect.prop(
		"encodedByteLength is consistent across multiple decodings of same wire format",
		[arbitraryValidNameUint8Array],
		([wireFormat]) =>
			Effect.gen(function* () {
				// Decode the same wire format multiple times
				const decoded1 = yield* decodeNameFromUint8Array(wireFormat);
				const decoded2 = yield* decodeNameFromUint8Array(wireFormat);

				// EncodedByteLength should be identical
				expect(decoded1.encodedByteLength).toBe(decoded2.encodedByteLength);

				// Content should be identical
				expect(decoded1.labels.length).toBe(decoded2.labels.length);
				for (let i = 0; i < decoded1.labels.length; i++) {
					expect(decoded1.labels[i]).toEqual(decoded2.labels[i]);
				}
			}),
	);

	it.effect("validates Name struct type structure", () =>
		Effect.gen(function* () {
			const wireFormat = new Uint8Array([4, 116, 101, 115, 116, 0]); // "test"
			const decoded = yield* decodeNameFromUint8Array(wireFormat);

			// Verify it satisfies Name struct interface
			expect(typeof decoded).toBe("object");
			expect(decoded.labels).toBeDefined();
			expect(Array.isArray(decoded.labels)).toBe(true);
			expect(typeof decoded.encodedByteLength).toBe("number");

			// Verify labels array can be used properly
			expect(decoded.labels.length).toBeGreaterThan(0);
			expect(decoded.labels[0]).toBeInstanceOf(Uint8Array);

			// Verify labels array methods work
			const mapped = decoded.labels.map((label) => label.length);
			expect(mapped).toEqual([4]);

			// Verify for...of iteration works on labels
			let count = 0;
			for (const label of decoded.labels) {
				expect(label).toBeInstanceOf(Uint8Array);
				count++;
			}
			expect(count).toBe(1);
		}),
	);
});
