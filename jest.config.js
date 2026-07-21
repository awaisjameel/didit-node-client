/** @type {import('jest').Config} */
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  roots: ["<rootDir>/src"],
  testMatch: ["**/__tests__/**/*.ts", "**/?(*.)+(spec|test).ts"],
  transform: {
    "^.+\\.ts$": ["ts-jest", { tsconfig: "tsconfig.jest.json" }],
  },
  moduleFileExtensions: ["ts", "js", "json", "node"],
  collectCoverageFrom: ["src/**/*.ts", "!src/**/__tests__/**", "!src/types/**"],
  clearMocks: true,
};
