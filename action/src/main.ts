import * as core from '@actions/core';
import {Utils} from './utils';

async function main() {
    try {
        core.startGroup('Frogbot');
        const eventName : string = Utils.setFrogbotEnv();
        await Utils.addToPath();
        switch (eventName) {
            case "pull_request":
            case "pull_request_target":
                await Utils.execScanPullRequest();
                break;
            case "push":
            case "schedule":
            case "workflow_dispatch":
                await Utils.execCreateFixPullRequests();
                break;
            default:
                core.setFailed(eventName + " event is not supported by Frogbot");
        }
    } catch (error) {
        core.setFailed((<any>error).message);
    } finally {
        core.endGroup();
    }
}

main();
