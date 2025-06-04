import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		// Test environment: 'node' or 'jsdom'
		environment: "node",
		// Include test files matching this pattern
		include: ["**/*.test.ts", "**/*.spec.ts"],
		// Enable watch mode by default (optional)
		watch: false,
	},
});
