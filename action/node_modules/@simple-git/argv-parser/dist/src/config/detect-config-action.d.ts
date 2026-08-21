import type { ConfigScope } from '../args/parse-argv.types';
import { type Flag } from '../flags/flags.helpers';
import type { ConfigOperation } from './config.types';
export declare function detectConfigAction(flags: Flag[], positionals: string[]): ConfigOperation | null;
export declare function toOperation(scope: ConfigScope, operation: ConfigOperation): {
    key: string;
    value: string;
    scope: ConfigScope;
} | {
    key: string;
    scope: ConfigScope;
    value?: undefined;
};
