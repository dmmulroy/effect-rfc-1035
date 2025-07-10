import { Schema } from "effect";
import { uint8Array } from "effect/FastCheck";
import { Uint8ArrayFromSelf } from "effect/Schema";

export const Nibble = Schema.Number.pipe(
	Schema.between(0, 15, {
		identifier: "Nibble",
		description: "a 4-bit unsigned integer",
	}),
);

export const Uint3 = Schema.Number.pipe(
	Schema.between(0, 7, {
		identifier: "Uint3",
		description: "a 3-bit unsigned integer",
	}),
);

export type Bit = typeof Bit.Type;

export const Bit = Schema.Literal(0, 1).annotations({
	identifier: "Bit",
	description: "a 1-bit unsigned integer",
});

export type Uint8 = typeof Uint8.Type;

export const Uint8 = Schema.Number.pipe(
	Schema.between(0, 255, {
		identifier: "Byte",
		description: "a 8-bit unsigned integer",
	}),
);

export const Uint16 = Schema.Number.pipe(
	Schema.between(0, 65_535, {
		identifier: "Uint16",
		description: "a 16-bit unsigned integer",
	}),
);

export type Uint31 = typeof Uint31.Type;
export const Uint31 = Schema.Number.pipe(
	Schema.between(0, 2_147_483_647, {
		identifier: "Uint31",
		description: "a 31-bit unsigned integer",
	}),
);

export function isUint31(num: number): num is Uint31 {
	return Schema.is(Uint31)(num);
}

const DnsPacketCursorSchema = Schema.Struct({
	uint8Array: Uint8ArrayFromSelf,
	offset: Schema.Number,
}).pipe(
	Schema.mutable,
	Schema.annotations({
		identifier: "DnsPacketCursor",
		description: "Tracks the current byte offset during decoding",
	}),
);

export type DnsPacketCursor = typeof DnsPacketCursorSchema.Type;

export const DnsPacketCursor = {
	schema: DnsPacketCursorSchema,
	fromUint8Array: (
		uint8Array: Uint8Array,
		offset: number = 0,
	): DnsPacketCursor => ({
		uint8Array,
		offset,
	}),
} as const;
