import type { ParsedConfigActivity } from '../args/parse-argv.types';
import type { Vulnerability } from './vulnerability.types';
export declare function detectVulnerableConfigWrites({ write, }: ParsedConfigActivity): Generator<Vulnerability>;
