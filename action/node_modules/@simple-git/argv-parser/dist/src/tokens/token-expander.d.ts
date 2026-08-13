/** Parse a single raw token (e.g. `'-m'`, `'--amend'`, `'-uc'`) into one or
 *  more switch descriptors.  Values are not yet resolved for needsNext=true. */
export declare function expandToken(raw: string, spec?: import("./flag-specs").FlagSpec): Array<{
    name: string;
    value?: string;
    needsNext: boolean;
}>;
