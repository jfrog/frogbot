import type { ParsedConfigActivity } from '../args/parse-argv.types';
import { type Flag } from '../flags/flags.helpers';
export declare function collectConfigAccess(task: string | null, flags: Flag[], positionals: string[]): ParsedConfigActivity;
