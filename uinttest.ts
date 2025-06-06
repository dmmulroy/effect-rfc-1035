import { Schema } from "effect";

const Label = Schema.Uint8ArrayFromSelf.pipe(
	// @ts-expect-error
	Schema.maxItems(63),
	Schema.annotations({
		identifier: "Label",
		description: "63 octets or less",
	}),
);

const decodeSync = Schema.decodeSync(Label);

const uint8Array = new Uint8Array(Array.from({ length: 64 }, (_, idx) => idx));

console.log(decodeSync(uint8Array));
