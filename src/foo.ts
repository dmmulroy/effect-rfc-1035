function testOffsetExtraction() {
	// Example uint16 with top two bits set (pointer indicator)
	const uint16 = 0b1100000000000001; // 0xC001

	// Method 1: shift left then unsigned shift right
	const offsetShift = (uint16 << 2) >>> 2;

	// Method 2: mask with 0x3FFF
	const offsetMask = uint16 & 0x3fff;

	console.log("Original uint16: 0x" + uint16.toString(2));
	console.log("foo: " + (uint16 << 2).toString(2)); // 0b0000000000000100
	console.log("bar: " + (uint16 << 2).toString(2));
	console.log("Offset (shift method): 0x" + offsetShift.toString(2));
	console.log("Offset (mask method): 0x" + offsetMask.toString(2));

	if (offsetShift !== offsetMask) {
		console.log("Test passed: The two methods produce different results.");
	} else {
		console.log("Test failed: The two methods produce the same result.");
	}
}

testOffsetExtraction();
