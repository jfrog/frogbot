export interface Flag {
    name: string;
    value?: string;
    /** Value came from the next token rather than being embedded after `=`. */
    absorbedNext: boolean;
    /** Switch appeared before the git sub-command. */
    isGlobal: boolean;
}
export declare function scopedFlags(flags: Flag[], scope: 'global' | 'task'): Generator<Flag, void, unknown>;
