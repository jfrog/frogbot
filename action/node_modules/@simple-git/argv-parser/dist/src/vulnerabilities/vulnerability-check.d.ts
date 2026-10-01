/**
 * Retrieves just the vulnerabilities identified in the supplied varargs tokens
 * and environment variables.
 */
export declare function vulnerabilityCheck(tokens: readonly string[], env: Record<string, unknown>): import("./vulnerability.types").Vulnerability[];
