/**
 * Wraps one or more file paths in an object that `parseCli` recognises as
 * explicit pathspecs, routing them to `ParsedCLI.paths` regardless of whether
 * a `--` separator token is present.
 */
export declare function pathspec(...paths: string[]): string;
export declare function isPathSpec(value: unknown): value is string;
export declare function toPaths(value: string): string[];
