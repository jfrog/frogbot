import type { ParsedArgv } from './parse-argv.types';
/**
 * Parse the tokens that would be forwarded to a `git` child-process and
 * return a structured summary of what the invocation does.
 */
export declare function parseArgv(...tokens: readonly unknown[]): ParsedArgv;
