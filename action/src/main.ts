import * as core from '@actions/core';
import { Utils } from './utils';

async function main() {
    try {
        core.startGroup('Frogbot');
        Utils.setFrogbotEnv();
        await Utils.addToPath();
        await Utils.execScanPullRequest();
    } catch (error) {
        core.setFailed((<any>error).message);
    } finally {
        core.endGroup();
    }
}

main();
