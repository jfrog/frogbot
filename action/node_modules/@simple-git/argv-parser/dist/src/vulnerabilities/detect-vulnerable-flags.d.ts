import type { Flag } from '../flags/flags.helpers';
import type { Vulnerability } from './vulnerability.types';
export declare function detectVulnerableFlags(task: null | string, flags: Flag[]): Generator<Vulnerability>;
