export interface FlagSpec {
    readonly short: ReadonlyMap<string, boolean>;
    readonly long: ReadonlySet<string>;
}
export declare const GLOBAL: FlagSpec;
export declare function getFlagSpecForTask(task?: string | null): {
    short: Map<string, boolean>;
    long: ReadonlySet<string>;
};
