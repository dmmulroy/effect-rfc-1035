import { describe, expect, it } from "@effect/vitest";
import { Effect } from "effect";
import {
	arbitraryComplexMultiSectionMessage,
	arbitraryComprehensiveQType,
	arbitraryComprehensiveQClass,
	arbitraryRealisticResourceRecord,
	arbitraryIdnDomainName,
} from "./arbitraries";

type ComplexMessage = {
	header: {
		id: number;
		qr: number;
		opcode: number;
		aa: number;
		tc: number;
		rd: number;
		ra: number;
		z: number;
		rcode: number;
		qdcount: number;
		ancount: number;
		nscount: number;
		arcount: number;
	};
	questions: Array<{
		qname: Uint8Array[];
		qtype: number;
		qclass: number;
	}>;
	answers: Array<{
		name: Uint8Array[];
		type: number;
		class: number;
		ttl: number;
		rdlength: number;
		rdata: Uint8Array;
	}>;
	authority: Array<{
		name: Uint8Array[];
		type: number;
		class: number;
		ttl: number;
		rdlength: number;
		rdata: Uint8Array;
	}>;
	additional: Array<{
		name: Uint8Array[];
		type: number;
		class: number;
		ttl: number;
		rdlength: number;
		rdata: Uint8Array;
	}>;
};

describe("Complex Multi-Section DNS Message Testing", () => {
	it.effect.prop(
		"should handle realistic DNS response scenarios with multiple sections",
		[arbitraryComplexMultiSectionMessage],
		([message]: [ComplexMessage]) =>
			Effect.gen(function* () {
				// Validate section count consistency
				expect(message.questions.length).toBe(message.header.qdcount);
				expect(message.answers.length).toBe(message.header.ancount);
				expect(message.authority.length).toBe(message.header.nscount);
				expect(message.additional.length).toBe(message.header.arcount);

				// Validate response characteristics
				if (message.header.qr === 1) {
					// Response messages should have answers or authority records
					const totalRecords = message.header.ancount + message.header.nscount;
					expect(totalRecords).toBeGreaterThan(0);
				}

				// Validate cross-references between sections
				if (message.answers.length > 0 && message.additional.length > 0) {
					// Additional records should relate to answers/authority
					const answerNames = message.answers.map((a: any) => 
						a.name.map((label: Uint8Array) => new TextDecoder().decode(label)).join(".")
					);
					const additionalNames = message.additional.map((a: any) => 
						a.name.map((label: Uint8Array) => new TextDecoder().decode(label)).join(".")
					);
					
					// At least some additional records should reference answer domains
					const hasRelatedAdditional = additionalNames.some((addName: string) =>
						answerNames.some((ansName: string) => addName.includes(ansName.split(".")[0] || ""))
					);
					expect(hasRelatedAdditional || message.additional.length === 0).toBe(true);
				}
			})
	);

	it("should validate A record with NS authority scenario", () => {
		const message = {
			header: {
				id: 12345,
				qr: 1,
				opcode: 0,
				aa: 1,
				tc: 0,
				rd: 1,
				ra: 1,
				z: 0,
				rcode: 0,
				qdcount: 1,
				ancount: 1,
				nscount: 2,
				arcount: 2,
			},
			questions: [{
				qname: [
					new Uint8Array([101, 120, 97, 109, 112, 108, 101]), // "example"
					new Uint8Array([99, 111, 109]), // "com"
				],
				qtype: 1, // A
				qclass: 1, // IN
			}],
			answers: [{
				name: [
					new Uint8Array([101, 120, 97, 109, 112, 108, 101]), // "example"
					new Uint8Array([99, 111, 109]), // "com"
				],
				type: 1, // A
				class: 1, // IN
				ttl: 3600,
				rdlength: 4,
				rdata: new Uint8Array([192, 168, 1, 1]),
			}],
			authority: [
				{
					name: [new Uint8Array([99, 111, 109])], // "com"
					type: 2, // NS
					class: 1,
					ttl: 86400,
					rdlength: 17,
					rdata: new Uint8Array([3, 110, 115, 49, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0]),
				},
				{
					name: [new Uint8Array([99, 111, 109])], // "com"
					type: 2, // NS
					class: 1,
					ttl: 86400,
					rdlength: 17,
					rdata: new Uint8Array([3, 110, 115, 50, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0]),
				}
			],
			additional: [
				{
					name: [
						new Uint8Array([110, 115, 49]), // "ns1"
						new Uint8Array([101, 120, 97, 109, 112, 108, 101]), // "example"
						new Uint8Array([99, 111, 109]), // "com"
					],
					type: 1, // A
					class: 1,
					ttl: 3600,
					rdlength: 4,
					rdata: new Uint8Array([192, 168, 1, 10]),
				},
				{
					name: [
						new Uint8Array([110, 115, 50]), // "ns2"
						new Uint8Array([101, 120, 97, 109, 112, 108, 101]), // "example"
						new Uint8Array([99, 111, 109]), // "com"
					],
					type: 1, // A
					class: 1,
					ttl: 3600,
					rdlength: 4,
					rdata: new Uint8Array([192, 168, 1, 11]),
				}
			],
		};

		// Validate authoritative response structure
		expect(message.header.qr).toBe(1); // Response
		expect(message.header.aa).toBe(1); // Authoritative
		expect(message.header.rcode).toBe(0); // No error

		// Validate section counts match header
		expect(message.questions.length).toBe(message.header.qdcount);
		expect(message.answers.length).toBe(message.header.ancount);
		expect(message.authority.length).toBe(message.header.nscount);
		expect(message.additional.length).toBe(message.header.arcount);

		// Validate answer matches question
		expect(message.answers[0]?.type).toBe(message.questions[0]?.qtype);
		expect(message.answers[0]?.class).toBe(message.questions[0]?.qclass);

		// Validate authority records are NS type
		message.authority.forEach(auth => {
			expect(auth.type).toBe(2); // NS
		});

		// Validate additional records provide A records for NS servers
		message.additional.forEach(add => {
			expect(add.type).toBe(1); // A
			expect(add.rdlength).toBe(4); // IPv4 address
		});
	});

	it("should validate CNAME chain resolution", () => {
		const message = {
			header: {
				id: 54321,
				qr: 1,
				opcode: 0,
				aa: 0,
				tc: 0,
				rd: 1,
				ra: 1,
				z: 0,
				rcode: 0,
				qdcount: 1,
				ancount: 2,
				nscount: 0,
				arcount: 0,
			},
			questions: [{
				qname: [
					new Uint8Array([119, 119, 119]), // "www"
					new Uint8Array([101, 120, 97, 109, 112, 108, 101]), // "example"
					new Uint8Array([99, 111, 109]), // "com"
				],
				qtype: 1, // A
				qclass: 1,
			}],
			answers: [
				{
					name: [
						new Uint8Array([119, 119, 119]), // "www"
						new Uint8Array([101, 120, 97, 109, 112, 108, 101]), // "example"
						new Uint8Array([99, 111, 109]), // "com"
					],
					type: 5, // CNAME
					class: 1,
					ttl: 300,
					rdlength: 17,
					rdata: new Uint8Array([3, 119, 119, 119, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0]),
				},
				{
					name: [
						new Uint8Array([119, 119, 119]), // "www"
						new Uint8Array([101, 120, 97, 109, 112, 108, 101]), // "example"
						new Uint8Array([99, 111, 109]), // "com"
					],
					type: 1, // A
					class: 1,
					ttl: 3600,
					rdlength: 4,
					rdata: new Uint8Array([203, 0, 113, 1]),
				}
			],
		};

		// Validate CNAME chain structure
		expect(message.answers.length).toBe(2);
		expect(message.answers[0]?.type).toBe(5); // CNAME
		expect(message.answers[1]?.type).toBe(1); // A

		// CNAME should have lower TTL than final A record
		expect(message.answers[0]?.ttl).toBeLessThanOrEqual(message.answers[1]?.ttl || 0);

		// Both records should have same name (the queried name)
		const name1 = message.answers[0]?.name.map(l => new TextDecoder().decode(l)).join(".");
		const name2 = message.answers[1]?.name.map(l => new TextDecoder().decode(l)).join(".");
		expect(name1).toBe(name2);
	});

	it("should validate MX record with additional A records", () => {
		const message = {
			header: {
				id: 65535,
				qr: 1,
				opcode: 0,
				aa: 1,
				tc: 0,
				rd: 1,
				ra: 1,
				z: 0,
				rcode: 0,
				qdcount: 1,
				ancount: 2,
				nscount: 0,
				arcount: 2,
			},
			questions: [{
				qname: [
					new Uint8Array([101, 120, 97, 109, 112, 108, 101]), // "example"
					new Uint8Array([99, 111, 109]), // "com"
				],
				qtype: 15, // MX
				qclass: 1,
			}],
			answers: [
				{
					name: [
						new Uint8Array([101, 120, 97, 109, 112, 108, 101]), // "example"
						new Uint8Array([99, 111, 109]), // "com"
					],
					type: 15, // MX
					class: 1,
					ttl: 3600,
					rdlength: 20,
					rdata: new Uint8Array([0, 10, 4, 109, 97, 105, 108, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0]),
				},
				{
					name: [
						new Uint8Array([101, 120, 97, 109, 112, 108, 101]), // "example"
						new Uint8Array([99, 111, 109]), // "com"
					],
					type: 15, // MX
					class: 1,
					ttl: 3600,
					rdlength: 21,
					rdata: new Uint8Array([0, 20, 5, 109, 97, 105, 108, 50, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0]),
				}
			],
			additional: [
				{
					name: [
						new Uint8Array([109, 97, 105, 108]), // "mail"
						new Uint8Array([101, 120, 97, 109, 112, 108, 101]), // "example"
						new Uint8Array([99, 111, 109]), // "com"
					],
					type: 1, // A
					class: 1,
					ttl: 3600,
					rdlength: 4,
					rdata: new Uint8Array([192, 168, 1, 20]),
				},
				{
					name: [
						new Uint8Array([109, 97, 105, 108, 50]), // "mail2"
						new Uint8Array([101, 120, 97, 109, 112, 108, 101]), // "example"
						new Uint8Array([99, 111, 109]), // "com"
					],
					type: 1, // A
					class: 1,
					ttl: 3600,
					rdlength: 4,
					rdata: new Uint8Array([192, 168, 1, 21]),
				}
			],
		};

		// Validate MX record structure
		expect(message.questions[0]?.qtype).toBe(15); // MX query
		expect(message.answers.every(a => a.type === 15)).toBe(true); // All answers are MX

		// Validate MX preference ordering (lower preference = higher priority)
		const mx1Preference = (message.answers[0]?.rdata[0] || 0) << 8 | (message.answers[0]?.rdata[1] || 0);
		const mx2Preference = (message.answers[1]?.rdata[0] || 0) << 8 | (message.answers[1]?.rdata[1] || 0);
		expect(mx1Preference).toBeLessThan(mx2Preference); // First MX has higher priority

		// Validate additional records provide A records for MX targets
		expect(message.additional.every(a => a.type === 1)).toBe(true); // All additional are A records
		expect(message.additional.every(a => a.rdlength === 4)).toBe(true); // IPv4 addresses

		// Additional records should correspond to MX targets
		const additionalNames = message.additional.map(a => 
			a.name.map(l => new TextDecoder().decode(l)).join(".")
		);
		expect(additionalNames).toContain("mail.example.com");
		expect(additionalNames).toContain("mail2.example.com");
	});
});

describe("Comprehensive QTYPE/QCLASS Testing", () => {
	it.effect.prop(
		"should handle all standard DNS record types and classes",
		[arbitraryComprehensiveQType, arbitraryComprehensiveQClass],
		([qtype, qclass]: [number, number]) =>
			Effect.gen(function* () {
				// Validate QTYPE is within valid range
				expect(qtype).toBeGreaterThanOrEqual(1);
				expect(qtype).toBeLessThanOrEqual(16);

				// Validate QCLASS is standard
				expect([1, 3, 4]).toContain(qclass);

				// Validate type-specific constraints
				if (qtype === 1) { // A record
					// A records should be IN class primarily
					expect([1, 3, 4]).toContain(qclass);
				}
				if (qtype === 15) { // MX record
					// MX records are typically IN class
					expect([1, 3, 4]).toContain(qclass);
				}
			})
	);

	it.effect.prop(
		"should validate realistic resource records with proper RDATA",
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

				// Validate type-specific RDATA constraints
				if (record.type === 1) { // A record
					expect(record.rdlength).toBe(4); // IPv4 address
					expect(record.rdata.length).toBe(4);
				}
				if (record.type === 15) { // MX record
					expect(record.rdlength).toBeGreaterThanOrEqual(3); // At least preference + minimal domain
				}
				if (record.type === 16) { // TXT record
					expect(record.rdlength).toBeGreaterThanOrEqual(1); // At least one byte for length
				}
			})
	);

	it("should validate specific record type formats", () => {
		// A record validation
		const aRecord = {
			name: [new Uint8Array([101, 120, 97, 109, 112, 108, 101]), new Uint8Array([99, 111, 109])],
			type: 1,
			class: 1,
			ttl: 3600,
			rdlength: 4,
			rdata: new Uint8Array([192, 168, 1, 1]),
		};
		expect(aRecord.rdlength).toBe(4);
		expect(aRecord.rdata.length).toBe(4);

		// MX record validation
		const mxRecord = {
			name: [new Uint8Array([101, 120, 97, 109, 112, 108, 101]), new Uint8Array([99, 111, 109])],
			type: 15,
			class: 1,
			ttl: 3600,
			rdlength: 20,
			rdata: new Uint8Array([0, 10, 4, 109, 97, 105, 108, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0]),
		};
		expect(mxRecord.rdlength).toBe(20);
		expect(mxRecord.rdata.length).toBe(20);
		// Validate MX preference field
		const preference = (mxRecord.rdata[0] || 0) << 8 | (mxRecord.rdata[1] || 0);
		expect(preference).toBe(10);

		// TXT record validation
		const txtRecord = {
			name: [new Uint8Array([101, 120, 97, 109, 112, 108, 101]), new Uint8Array([99, 111, 109])],
			type: 16,
			class: 1,
			ttl: 3600,
			rdlength: 12,
			rdata: new Uint8Array([11, 104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100]), // "hello world"
		};
		expect(txtRecord.rdlength).toBe(12);
		expect(txtRecord.rdata[0]).toBe(11); // Text length
		expect(new TextDecoder().decode(txtRecord.rdata.slice(1))).toBe("hello world");
	});
});

describe("IDN/Punycode Testing", () => {
	it.effect.prop(
		"should handle internationalized domain names with punycode encoding",
		[arbitraryIdnDomainName],
		([domainName]: [Uint8Array[]]) =>
			Effect.gen(function* () {
				// Validate domain structure
				expect(domainName.length).toBeGreaterThan(0);
				expect(domainName.length).toBeLessThanOrEqual(127); // Max labels

				// Calculate total encoded length
				const totalLength = domainName.reduce((sum: number, label: Uint8Array) => sum + label.length + 1, 0) + 1;
				expect(totalLength).toBeLessThanOrEqual(255); // RFC limit

				// Check for punycode labels (xn-- prefix)
				const hasPunycode = domainName.some((label: Uint8Array) => {
					const labelStr = new TextDecoder().decode(label);
					return labelStr.startsWith("xn--");
				});

				if (hasPunycode) {
					// Validate punycode format
					domainName.forEach((label: Uint8Array) => {
						const labelStr = new TextDecoder().decode(label);
						if (labelStr.startsWith("xn--")) {
							expect(labelStr.length).toBeGreaterThanOrEqual(4); // "xn--" + content
							expect(labelStr.length).toBeLessThanOrEqual(63); // Max label length
							// Punycode should only contain ASCII
							expect(/^[a-zA-Z0-9-]+$/.test(labelStr)).toBe(true);
						}
					});
				}
			})
	);

	it("should validate specific punycode scenarios", () => {
		// ASCII-compatible encoding (ACE) example
		const punycodeLabel = new Uint8Array([120, 110, 45, 45, 110, 120, 97, 109, 101, 49, 97]); // "xn--nxamel1a"
		const labelStr = new TextDecoder().decode(punycodeLabel);
		
		expect(labelStr).toMatch(/^xn--[a-zA-Z0-9]+$/);
		expect(labelStr.length).toBeLessThanOrEqual(63);

		// Mixed ASCII/Unicode domain
		const mixedDomain = [
			new Uint8Array([116, 101, 115, 116]), // "test"
			new Uint8Array([120, 110, 45, 45, 102, 115, 113, 117, 56, 48, 97]), // "xn--fsqu80a"
			new Uint8Array([111, 114, 103]), // "org"
		];

		const totalLength = mixedDomain.reduce((sum, label) => sum + label.length + 1, 0) + 1;
		expect(totalLength).toBeLessThanOrEqual(255);

		// Validate each label
		mixedDomain.forEach(label => {
			expect(label.length).toBeGreaterThan(0);
			expect(label.length).toBeLessThanOrEqual(63);
		});
	});

	it("should handle maximum length punycode name", () => {
		// 63-character punycode label (maximum allowed)
		const maxPunycodeLabel = new Uint8Array(Array.from("xn--" + "a".repeat(59), c => c.charCodeAt(0)));
		
		expect(maxPunycodeLabel.length).toBe(63);
		
		const labelStr = new TextDecoder().decode(maxPunycodeLabel);
		expect(labelStr).toMatch(/^xn--a+$/);
		expect(labelStr.length).toBe(63);

		// Domain with max punycode label should still be valid
		const domainWithMaxLabel = [maxPunycodeLabel, new Uint8Array([99, 111, 109])];
		const totalLength = domainWithMaxLabel.reduce((sum, label) => sum + label.length + 1, 0) + 1;
		expect(totalLength).toBeLessThanOrEqual(255);
	});
});