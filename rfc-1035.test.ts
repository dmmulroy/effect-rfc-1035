import { describe, expect, it } from "@effect/vitest";
import { Effect, Exit, FastCheck as fc } from "effect";
import { decodeHeader, encodeHeader } from ".";

const arbitraryDnsHeaderUint8Array = fc.uint8Array({
	maxLength: 12,
	minLength: 12,
});

describe("rfc-1035", () => {
	describe("header", () => {
		it.effect.prop(
			"successfully decodes a Uint8Array to a Header",
			[arbitraryDnsHeaderUint8Array],
			([uint8Array]) =>
				Effect.gen(function* () {
					yield* Effect.sync(() => console.log("run"));
					const result = yield* Effect.exit(decodeHeader(uint8Array));
					expect(Exit.isSuccess(result)).toBe(true);
				}),
		);

		it.effect.prop(
			"fails to decode if Uint8Array is not 12 bytes",
			[
				fc
					.uint8Array({ minLength: 0, maxLength: 24 })
					.filter((arr) => arr.length !== 12),
			],
			([uint8Array]) =>
				Effect.gen(function* () {
					yield* Effect.sync(() => console.log("run"));
					const result = yield* Effect.exit(decodeHeader(uint8Array));
					expect(Exit.isFailure(result)).toBe(true);
				}),
		);

		it.effect.prop(
			"encodeHeader and decodeHeader are inverses (roundtrip)",
			[arbitraryDnsHeaderUint8Array],
			([uint8Array]) =>
				Effect.gen(function* () {
					yield* Effect.sync(() => console.log("run"));
					const decoded = yield* decodeHeader(uint8Array);

					const encoded = yield* encodeHeader(decoded);
					expect(Array.from(encoded)).toEqual(Array.from(uint8Array));
				}),
		);

		it.effect("decodes all-zero header", () =>
			Effect.gen(function* () {
				yield* Effect.sync(() => console.log("run"));
				const arr = new Uint8Array(12);
				const result = yield* Effect.exit(decodeHeader(arr));
				expect(Exit.isSuccess(result)).toBe(true);
			}),
		);

		it.effect("decodes all-ones header", () =>
			Effect.gen(function* () {
				yield* Effect.sync(() => console.log("run"));
				const arr = new Uint8Array(12).fill(0xff);
				const result = yield* Effect.exit(decodeHeader(arr));
				expect(Exit.isSuccess(result)).toBe(true);
			}),
		);

		it.effect.prop(
			"decoding then encoding yields a Uint8Array of length 12",
			[arbitraryDnsHeaderUint8Array],
			([uint8Array]) =>
				Effect.gen(function* () {
					yield* Effect.sync(() => console.log("run"));
					const header = yield* decodeHeader(uint8Array);
					const encoded = yield* encodeHeader(header);
					expect(encoded.length).toBe(12);
				}),
		);
	});
});
