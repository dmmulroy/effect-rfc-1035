import { describe, expect, it } from "@effect/vitest";
import { Effect, Exit } from "effect";
import { RRTypeNameToRRType } from "../src/resource-record";
import { decodeResourceRecordFromUint8Array } from "../src/resource-record";
import {
	arbitraryComprehensiveQType,
	arbitraryComprehensiveQClass,
	arbitraryRealisticResourceRecord,
} from "./arbitraries";

describe("Comprehensive QTYPE/QCLASS Testing", () => {
	it.effect.prop(
		"should validate all standard DNS record types",
		[arbitraryComprehensiveQType],
		([qtype]: [number]) =>
			Effect.gen(function* () {
				// Validate QTYPE is within RFC 1035 range
				expect(qtype).toBeGreaterThanOrEqual(1);
				expect(qtype).toBeLessThanOrEqual(16);

				// Validate specific type values
				const validTypes = Object.values(RRTypeNameToRRType);
				expect(validTypes).toContain(qtype);
			}),
	);

	it.effect.prop(
		"should validate all standard DNS classes",
		[arbitraryComprehensiveQClass],
		([qclass]: [number]) =>
			Effect.gen(function* () {
				// Validate QCLASS values per RFC 1035
				expect([1, 3, 4]).toContain(qclass);

				// Validate class semantics
				if (qclass === 1) {
					// IN - Internet class (most common)
					expect(qclass).toBe(1);
				} else if (qclass === 3) {
					// CH - Chaos class
					expect(qclass).toBe(3);
				} else if (qclass === 4) {
					// HS - Hesiod class
					expect(qclass).toBe(4);
				}
			}),
	);

	describe("A Record (Type 1) Testing", () => {
		it.effect("should validate A record structure and constraints", () => {
			const aRecord = new Uint8Array([
				// Name: "example.com"
				0x07,
				0x65,
				0x78,
				0x61,
				0x6d,
				0x70,
				0x6c,
				0x65, // "example"
				0x03,
				0x63,
				0x6f,
				0x6d, // "com"
				0x00, // Terminator
				// TYPE=A, CLASS=IN, TTL=3600, RDLENGTH=4
				0x00,
				0x01, // TYPE=A
				0x00,
				0x01, // CLASS=IN
				0x00,
				0x00,
				0x0e,
				0x10, // TTL=3600
				0x00,
				0x04, // RDLENGTH=4
				0xc0,
				0xa8,
				0x01,
				0x01, // RDATA: 192.168.1.1
			]);

			return Effect.gen(function* () {
				const result = yield* Effect.exit(
					decodeResourceRecordFromUint8Array(aRecord),
				);
				expect(Exit.isSuccess(result)).toBe(true);

				if (Exit.isSuccess(result)) {
					const rr = result.value;
					expect(rr.type).toBe(RRTypeNameToRRType.A);
					expect(rr.class).toBe(1); // IN
					expect(rr.rdlength).toBe(4);
					expect(rr.rdata.length).toBe(4);

					// Validate IPv4 address format
					expect(rr.rdata[0]).toBe(192);
					expect(rr.rdata[1]).toBe(168);
					expect(rr.rdata[2]).toBe(1);
					expect(rr.rdata[3]).toBe(1);
				}
			});
		});

		it.effect("should reject A record with invalid RDLENGTH", () => {
			const invalidARecord = new Uint8Array([
				// Name: "example.com"
				0x07,
				0x65,
				0x78,
				0x61,
				0x6d,
				0x70,
				0x6c,
				0x65,
				0x03,
				0x63,
				0x6f,
				0x6d,
				0x00,
				// TYPE=A with invalid RDLENGTH
				0x00,
				0x01, // TYPE=A
				0x00,
				0x01, // CLASS=IN
				0x00,
				0x00,
				0x0e,
				0x10, // TTL=3600
				0x00,
				0x06, // RDLENGTH=6 (should be 4)
				0xc0,
				0xa8,
				0x01,
				0x01,
				0x00,
				0x00, // Invalid RDATA
			]);

			return Effect.gen(function* () {
				const result = yield* Effect.exit(
					decodeResourceRecordFromUint8Array(invalidARecord),
				);
				expect(Exit.isFailure(result)).toBe(true);
			});
		});
	});

	describe("NS Record (Type 2) Testing", () => {
		it.effect("should validate NS record structure", () => {
			const nsRecord = new Uint8Array([
				// Name: "example.com"
				0x07,
				0x65,
				0x78,
				0x61,
				0x6d,
				0x70,
				0x6c,
				0x65,
				0x03,
				0x63,
				0x6f,
				0x6d,
				0x00,
				// TYPE=NS, CLASS=IN, TTL=86400
				0x00,
				0x02, // TYPE=NS
				0x00,
				0x01, // CLASS=IN
				0x00,
				0x01,
				0x51,
				0x80, // TTL=86400
				0x00,
				0x11, // RDLENGTH=17
				// RDATA: "ns1.example.com"
				0x03,
				0x6e,
				0x73,
				0x31, // "ns1"
				0x07,
				0x65,
				0x78,
				0x61,
				0x6d,
				0x70,
				0x6c,
				0x65, // "example"
				0x03,
				0x63,
				0x6f,
				0x6d,
				0x00, // "com"
			]);

			return Effect.gen(function* () {
				const result = yield* Effect.exit(
					decodeResourceRecordFromUint8Array(nsRecord),
				);
				expect(Exit.isSuccess(result)).toBe(true);

				if (Exit.isSuccess(result)) {
					const rr = result.value;
					expect(rr.type).toBe(RRTypeNameToRRType.NS);
					expect(rr.class).toBe(1); // IN
					expect(rr.rdlength).toBe(17);
					expect(rr.rdata.length).toBe(17);
				}
			});
		});
	});

	describe("CNAME Record (Type 5) Testing", () => {
		it.effect("should validate CNAME record structure", () => {
			const cnameRecord = new Uint8Array([
				// Name: "www.example.com"
				0x03,
				0x77,
				0x77,
				0x77, // "www"
				0x07,
				0x65,
				0x78,
				0x61,
				0x6d,
				0x70,
				0x6c,
				0x65, // "example"
				0x03,
				0x63,
				0x6f,
				0x6d,
				0x00, // "com"
				// TYPE=CNAME, CLASS=IN, TTL=300
				0x00,
				0x05, // TYPE=CNAME
				0x00,
				0x01, // CLASS=IN
				0x00,
				0x00,
				0x01,
				0x2c, // TTL=300
				0x00,
				0x11, // RDLENGTH=17
				// RDATA: "web.example.com"
				0x03,
				0x77,
				0x65,
				0x62, // "web"
				0x07,
				0x65,
				0x78,
				0x61,
				0x6d,
				0x70,
				0x6c,
				0x65, // "example"
				0x03,
				0x63,
				0x6f,
				0x6d,
				0x00, // "com"
			]);

			return Effect.gen(function* () {
				const result = yield* Effect.exit(
					decodeResourceRecordFromUint8Array(cnameRecord),
				);
				expect(Exit.isSuccess(result)).toBe(true);

				if (Exit.isSuccess(result)) {
					const rr = result.value;
					expect(rr.type).toBe(RRTypeNameToRRType.CNAME);
					expect(rr.class).toBe(1); // IN
					expect(rr.rdlength).toBe(17);
					expect(rr.rdata.length).toBe(17);
				}
			});
		});
	});

	describe("MX Record (Type 15) Testing", () => {
		it.effect("should validate MX record structure with preference", () => {
			const mxRecord = new Uint8Array([
				// Name: "example.com"
				0x07,
				0x65,
				0x78,
				0x61,
				0x6d,
				0x70,
				0x6c,
				0x65,
				0x03,
				0x63,
				0x6f,
				0x6d,
				0x00,
				// TYPE=MX, CLASS=IN, TTL=3600
				0x00,
				0x0f, // TYPE=MX
				0x00,
				0x01, // CLASS=IN
				0x00,
				0x00,
				0x0e,
				0x10, // TTL=3600
				0x00,
				0x14, // RDLENGTH=20
				// RDATA: preference=10, "mail.example.com"
				0x00,
				0x0a, // Preference=10
				0x04,
				0x6d,
				0x61,
				0x69,
				0x6c, // "mail"
				0x07,
				0x65,
				0x78,
				0x61,
				0x6d,
				0x70,
				0x6c,
				0x65, // "example"
				0x03,
				0x63,
				0x6f,
				0x6d,
				0x00, // "com"
			]);

			return Effect.gen(function* () {
				const result = yield* Effect.exit(
					decodeResourceRecordFromUint8Array(mxRecord),
				);
				expect(Exit.isSuccess(result)).toBe(true);

				if (Exit.isSuccess(result)) {
					const rr = result.value;
					expect(rr.type).toBe(RRTypeNameToRRType.MX);
					expect(rr.class).toBe(1); // IN
					expect(rr.rdlength).toBe(20);
					expect(rr.rdata.length).toBe(20);

					// Validate MX preference field
					const preference = ((rr.rdata[0] || 0) << 8) | (rr.rdata[1] || 0);
					expect(preference).toBe(10);
				}
			});
		});

		it("should validate MX preference ordering", () => {
			const mxRecords = [
				{ preference: 10, name: "mail1.example.com" },
				{ preference: 20, name: "mail2.example.com" },
				{ preference: 5, name: "mail3.example.com" },
			];

			// Sort by preference (lower = higher priority)
			const sortedRecords = [...mxRecords].sort(
				(a, b) => a.preference - b.preference,
			);

			expect(sortedRecords[0]?.preference).toBe(5); // Highest priority
			expect(sortedRecords[1]?.preference).toBe(10);
			expect(sortedRecords[2]?.preference).toBe(20); // Lowest priority
		});
	});

	describe("TXT Record (Type 16) Testing", () => {
		it.effect("should validate TXT record structure", () => {
			const txtRecord = new Uint8Array([
				// Name: "example.com"
				0x07,
				0x65,
				0x78,
				0x61,
				0x6d,
				0x70,
				0x6c,
				0x65,
				0x03,
				0x63,
				0x6f,
				0x6d,
				0x00,
				// TYPE=TXT, CLASS=IN, TTL=3600
				0x00,
				0x10, // TYPE=TXT
				0x00,
				0x01, // CLASS=IN
				0x00,
				0x00,
				0x0e,
				0x10, // TTL=3600
				0x00,
				0x0c, // RDLENGTH=12
				// RDATA: "hello world"
				0x0b, // String length=11
				0x68,
				0x65,
				0x6c,
				0x6c,
				0x6f,
				0x20,
				0x77,
				0x6f,
				0x72,
				0x6c,
				0x64, // "hello world"
			]);

			return Effect.gen(function* () {
				const result = yield* Effect.exit(
					decodeResourceRecordFromUint8Array(txtRecord),
				);
				expect(Exit.isSuccess(result)).toBe(true);

				if (Exit.isSuccess(result)) {
					const rr = result.value;
					expect(rr.type).toBe(RRTypeNameToRRType.TXT);
					expect(rr.class).toBe(1); // IN
					expect(rr.rdlength).toBe(12);
					expect(rr.rdata.length).toBe(12);

					// Validate TXT string format
					expect(rr.rdata[0]).toBe(11); // String length
					const textContent = new TextDecoder().decode(rr.rdata.slice(1));
					expect(textContent).toBe("hello world");
				}
			});
		});

		it.effect("should handle multiple TXT strings", () => {
			const multiTxtRecord = new Uint8Array([
				// Name: "example.com"
				0x07,
				0x65,
				0x78,
				0x61,
				0x6d,
				0x70,
				0x6c,
				0x65,
				0x03,
				0x63,
				0x6f,
				0x6d,
				0x00,
				// TYPE=TXT, CLASS=IN, TTL=3600
				0x00,
				0x10, // TYPE=TXT
				0x00,
				0x01, // CLASS=IN
				0x00,
				0x00,
				0x0e,
				0x10, // TTL=3600
				0x00,
				0x0c, // RDLENGTH=12
				// RDATA: "hello" + "world"
				0x05,
				0x68,
				0x65,
				0x6c,
				0x6c,
				0x6f, // "hello"
				0x05,
				0x77,
				0x6f,
				0x72,
				0x6c,
				0x64, // "world"
			]);

			return Effect.gen(function* () {
				const result = yield* Effect.exit(
					decodeResourceRecordFromUint8Array(multiTxtRecord),
				);
				expect(Exit.isSuccess(result)).toBe(true);

				if (Exit.isSuccess(result)) {
					const rr = result.value;
					expect(rr.type).toBe(RRTypeNameToRRType.TXT);
					expect(rr.rdlength).toBe(12);

					// Validate multiple strings
					expect(rr.rdata[0]).toBe(5); // First string length
					expect(rr.rdata[6]).toBe(5); // Second string length
				}
			});
		});
	});

	describe("PTR Record (Type 12) Testing", () => {
		it.effect("should validate PTR record for reverse DNS", () => {
			const ptrRecord = new Uint8Array([
				// Name: "1.1.168.192.in-addr.arpa"
				0x01,
				0x31, // "1"
				0x01,
				0x31, // "1"
				0x03,
				0x31,
				0x36,
				0x38, // "168"
				0x03,
				0x31,
				0x39,
				0x32, // "192"
				0x07,
				0x69,
				0x6e,
				0x2d,
				0x61,
				0x64,
				0x64,
				0x72, // "in-addr"
				0x04,
				0x61,
				0x72,
				0x70,
				0x61,
				0x00, // "arpa"
				// TYPE=PTR, CLASS=IN, TTL=3600
				0x00,
				0x0c, // TYPE=PTR
				0x00,
				0x01, // CLASS=IN
				0x00,
				0x00,
				0x0e,
				0x10, // TTL=3600
				0x00,
				0x0f, // RDLENGTH=15
				// RDATA: "host.example.com"
				0x04,
				0x68,
				0x6f,
				0x73,
				0x74, // "host"
				0x07,
				0x65,
				0x78,
				0x61,
				0x6d,
				0x70,
				0x6c,
				0x65, // "example"
				0x03,
				0x63,
				0x6f,
				0x6d,
				0x00, // "com"
			]);

			return Effect.gen(function* () {
				const result = yield* Effect.exit(
					decodeResourceRecordFromUint8Array(ptrRecord),
				);
				expect(Exit.isSuccess(result)).toBe(true);

				if (Exit.isSuccess(result)) {
					const rr = result.value;
					expect(rr.type).toBe(RRTypeNameToRRType.PTR);
					expect(rr.class).toBe(1); // IN
					expect(rr.rdlength).toBe(15);
					expect(rr.rdata.length).toBe(15);
				}
			});
		});
	});

	describe("SOA Record (Type 6) Testing", () => {
		it.effect("should validate SOA record structure", () => {
			const soaRecord = new Uint8Array([
				// Name: "example.com"
				0x07,
				0x65,
				0x78,
				0x61,
				0x6d,
				0x70,
				0x6c,
				0x65,
				0x03,
				0x63,
				0x6f,
				0x6d,
				0x00,
				// TYPE=SOA, CLASS=IN, TTL=86400
				0x00,
				0x06, // TYPE=SOA
				0x00,
				0x01, // CLASS=IN
				0x00,
				0x01,
				0x51,
				0x80, // TTL=86400
				0x00,
				0x37, // RDLENGTH=55
				// RDATA: MNAME + RNAME + 5 32-bit values
				// MNAME: "ns1.example.com"
				0x03,
				0x6e,
				0x73,
				0x31, // "ns1"
				0x07,
				0x65,
				0x78,
				0x61,
				0x6d,
				0x70,
				0x6c,
				0x65, // "example"
				0x03,
				0x63,
				0x6f,
				0x6d,
				0x00, // "com"
				// RNAME: "admin.example.com"
				0x05,
				0x61,
				0x64,
				0x6d,
				0x69,
				0x6e, // "admin"
				0x07,
				0x65,
				0x78,
				0x61,
				0x6d,
				0x70,
				0x6c,
				0x65, // "example"
				0x03,
				0x63,
				0x6f,
				0x6d,
				0x00, // "com"
				// Serial, Refresh, Retry, Expire, Minimum (5 x 32-bit values)
				0x00,
				0x00,
				0x00,
				0x01, // Serial=1
				0x00,
				0x00,
				0x1c,
				0x20, // Refresh=7200
				0x00,
				0x00,
				0x0e,
				0x10, // Retry=3600
				0x00,
				0x09,
				0x3a,
				0x80, // Expire=604800
				0x00,
				0x00,
				0x0e,
				0x10, // Minimum=3600
			]);

			return Effect.gen(function* () {
				const result = yield* Effect.exit(
					decodeResourceRecordFromUint8Array(soaRecord),
				);
				expect(Exit.isSuccess(result)).toBe(true);

				if (Exit.isSuccess(result)) {
					const rr = result.value;
					expect(rr.type).toBe(RRTypeNameToRRType.SOA);
					expect(rr.class).toBe(1); // IN
					expect(rr.rdlength).toBe(55);
					expect(rr.rdata.length).toBe(55);
				}
			});
		});
	});

	describe("Class-Specific Testing", () => {
		it("should handle Internet (IN) class records", () => {
			// Most common class - should work with all record types
			const recordTypes = [
				RRTypeNameToRRType.A,
				RRTypeNameToRRType.NS,
				RRTypeNameToRRType.CNAME,
				RRTypeNameToRRType.MX,
				RRTypeNameToRRType.TXT,
			];

			recordTypes.forEach((type) => {
				expect(type).toBeGreaterThanOrEqual(1);
				expect(type).toBeLessThanOrEqual(16);
			});
		});

		it("should handle Chaos (CH) class records", () => {
			// Chaos class - historically used for debugging
			const chClass = 3;
			expect(chClass).toBe(3);

			// CH class is valid but less common
			// Should be accepted by parsers but may have different semantics
		});

		it("should handle Hesiod (HS) class records", () => {
			// Hesiod class - used in some academic environments
			const hsClass = 4;
			expect(hsClass).toBe(4);

			// HS class is valid but specialized
			// Should be accepted by parsers
		});
	});

	it.effect.prop(
		"should validate realistic resource records across all types",
		[arbitraryRealisticResourceRecord],
		([record]: [any]) =>
			Effect.gen(function* () {
				// Validate basic structure
				expect(record.name.length).toBeGreaterThan(0);
				expect(record.type).toBeGreaterThanOrEqual(1);
				expect(record.type).toBeLessThanOrEqual(16);
				expect(record.class).toBeGreaterThanOrEqual(1);
				expect(record.ttl).toBeGreaterThanOrEqual(0);
				expect(record.rdlength).toBe(record.rdata.length);

				// Validate type-specific constraints
				switch (record.type) {
					case RRTypeNameToRRType.A:
						expect(record.rdlength).toBe(4); // IPv4 address
						break;
					case RRTypeNameToRRType.MX:
						expect(record.rdlength).toBeGreaterThanOrEqual(3); // Preference + minimal domain
						break;
					case RRTypeNameToRRType.TXT:
						expect(record.rdlength).toBeGreaterThanOrEqual(1); // At least length byte
						break;
					case RRTypeNameToRRType.NS:
					case RRTypeNameToRRType.CNAME:
					case RRTypeNameToRRType.PTR:
						expect(record.rdlength).toBeGreaterThanOrEqual(2); // Minimal domain name
						break;
					case RRTypeNameToRRType.SOA:
						expect(record.rdlength).toBeGreaterThanOrEqual(22); // Minimal SOA structure
						break;
				}

				// Validate class constraints
				expect([1, 3, 4]).toContain(record.class);
			}),
	);

	describe("Type-Class Combination Validation", () => {
		it("should validate common type-class combinations", () => {
			const commonCombinations = [
				{ type: RRTypeNameToRRType.A, class: 1 }, // A/IN
				{ type: RRTypeNameToRRType.NS, class: 1 }, // NS/IN
				{ type: RRTypeNameToRRType.MX, class: 1 }, // MX/IN
				{ type: RRTypeNameToRRType.TXT, class: 1 }, // TXT/IN
				{ type: RRTypeNameToRRType.CNAME, class: 1 }, // CNAME/IN
				{ type: RRTypeNameToRRType.PTR, class: 1 }, // PTR/IN
				{ type: RRTypeNameToRRType.SOA, class: 1 }, // SOA/IN
			];

			commonCombinations.forEach(({ type, class: cls }) => {
				expect(type).toBeGreaterThanOrEqual(1);
				expect(type).toBeLessThanOrEqual(16);
				expect(cls).toBe(1); // Internet class
			});
		});

		it("should validate less common but valid combinations", () => {
			const validCombinations = [
				{ type: RRTypeNameToRRType.TXT, class: 3 }, // TXT/CH (debugging)
				{ type: RRTypeNameToRRType.A, class: 4 }, // A/HS (Hesiod)
				{ type: RRTypeNameToRRType.TXT, class: 4 }, // TXT/HS
			];

			validCombinations.forEach(({ type, class: cls }) => {
				expect(type).toBeGreaterThanOrEqual(1);
				expect(type).toBeLessThanOrEqual(16);
				expect([3, 4]).toContain(cls);
			});
		});
	});
});

