/**
 * Jest Configuration
 *
 * Jest is a testing framework for JavaScript/TypeScript
 * Configuration for:
 * - Unit tests for services
 * - Component tests for React components
 * - API route tests
 * - Coverage reporting
 */

const nextJest = require('next/jest')

const createJestConfig = nextJest({
  // Provide the path to your Next.js app to load next.config.js and .env files in your test environment
  dir: './',
})

// Add any custom config to be passed to Jest
const customJestConfig = {
  setupFilesAfterEnv: ['<rootDir>/jest.setup.js'],
  // jsdom by default (components). API route tests opt into Node with a
  // `/** @jest-environment node */` docblock at the top of the file.
  testEnvironment: 'jest-environment-jsdom',
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
  },
  testMatch: [
    '**/__tests__/**/*.[jt]s?(x)',
    '**/?(*.)+(spec|test).[jt]s?(x)',
  ],
  collectCoverageFrom: [
    'src/**/*.{js,jsx,ts,tsx}',
    '!src/**/*.d.ts',
    '!src/**/*.stories.{js,jsx,ts,tsx}',
    '!src/**/__tests__/**',
  ],
  // No global coverageThreshold yet: current coverage is far below any useful
  // bar and a failing threshold would block CI. Re-add one (e.g. 50%) once the
  // service and API suites grow.
}

// createJestConfig is exported this way to ensure that next/jest can load the Next.js config which is async
module.exports = createJestConfig(customJestConfig)
