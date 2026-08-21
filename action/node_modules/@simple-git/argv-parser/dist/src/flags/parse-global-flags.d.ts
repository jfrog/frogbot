import type { Flag } from './flags.helpers';
export interface GlobalFlags {
    flags: Flag[];
    taskIndex: number;
}
export declare function parseGlobalFlags(tokens: readonly unknown[], flags?: Flag[]): GlobalFlags;
