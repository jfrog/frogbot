import * as core from '@actions/core';
import { Utils } from './utils';

async function main() {
    try {
        core.startGroup('Frogbot');
        Utils.setFrogbotEnv();
        const eventName : string =  Utils.getGitEventName();
        await Utils.addToPath();
        switch (eventName) {
            case "pull_request":
                await Utils.execScanPullRequest();
                break;
            case "push":
                await Utils.execCreateFixPullRequests();
                break;
        }
    } catch (error) {
        core.setFailed((<any>error).message);
    } finally {
        core.endGroup();
    }
}

main();
