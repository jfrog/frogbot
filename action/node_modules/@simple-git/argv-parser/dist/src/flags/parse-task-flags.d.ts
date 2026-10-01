import type { Flag } from './flags.helpers';
type TaskFlags = {
    flags: Flag[];
    positionals: string[];
    pathspecs: string[];
};
export declare function parseTaskFlags(tokens: readonly unknown[], task: string | null, flags?: Flag[]): TaskFlags;
export {};
