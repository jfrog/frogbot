import type { ParsedConfigActivity } from '../args/parse-argv.types';
import type { Vulnerability } from '../vulnerabilities/vulnerability.types';
export declare function parseEnv(raw: Record<string, unknown>): {
    config: ParsedConfigActivity;
    vulnerabilities: Vulnerability[];
};
