import { Either, ParseResult, SchemaAST } from "effect";
import { isError } from "effect/Predicate";
import type { Uint8 } from "./types";

export function getUint8(
	dataView: DataView,
	offset: number,
	ast: SchemaAST.AST,
): Either.Either<number, ParseResult.ParseIssue> {
	return ParseResult.try({
		try: () => dataView.getUint8(offset),
		catch(cause) {
			return new ParseResult.Type(
				ast,
				dataView,
				isError(cause) ? cause.message : "Malformed input",
			);
		},
	});
}

export function getUint16(
	dataView: DataView,
	offset: number,
	ast: SchemaAST.AST,
): Either.Either<number, ParseResult.ParseIssue> {
	return ParseResult.try({
		try: () => dataView.getUint16(offset, false),
		catch(cause) {
			return new ParseResult.Type(
				ast,
				dataView,
				isError(cause) ? cause.message : "Malformed input",
			);
		},
	});
}

export function getUint32(
	dataView: DataView,
	offset: number,
	ast: SchemaAST.AST,
): Either.Either<number, ParseResult.ParseIssue> {
	return ParseResult.try({
		try: () => dataView.getUint32(offset, false),
		catch(cause) {
			return new ParseResult.Type(
				ast,
				dataView,
				isError(cause) ? cause.message : "Malformed input",
			);
		},
	});
}

export function setUint8(
	dataView: DataView,
	offset: number,
	value: Uint8,
	ast: SchemaAST.AST,
): Either.Either<void, ParseResult.ParseIssue> {
	return ParseResult.try({
		try: () => dataView.setUint8(offset, value),
		catch(cause) {
			return new ParseResult.Type(
				ast,
				dataView,
				isError(cause) ? cause.message : "Malformed input",
			);
		},
	});
}

export function uint8ArraySet(
	target: Uint8Array,
	value: Uint8Array,
	offset: number,
	ast: SchemaAST.AST,
): Either.Either<void, ParseResult.ParseIssue> {
	return ParseResult.try({
		try: () => target.set(value, offset),
		catch(cause) {
			return new ParseResult.Type(
				ast,
				target,
				isError(cause) ? cause.message : "Malformed input",
			);
		},
	});
}