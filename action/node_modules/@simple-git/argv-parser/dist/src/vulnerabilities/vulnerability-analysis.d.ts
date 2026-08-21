import type { ParsedConfigActivity } from '../args/parse-argv.types';
import type { Flag } from '../flags/flags.helpers';
import type { Vulnerability } from './vulnerability.types';
export declare function vulnerabilityAnalysis(task: null | string, flags: Flag[], config: ParsedConfigActivity): Vulnerability[];
