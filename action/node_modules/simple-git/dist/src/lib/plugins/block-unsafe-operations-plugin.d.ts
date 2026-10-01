import type { SimpleGitPluginConfig } from '../types';
import type { SimpleGitPlugin } from './simple-git-plugin';
export declare function blockUnsafeOperationsPlugin(options?: SimpleGitPluginConfig['unsafe']): SimpleGitPlugin<'spawn.args'>;
