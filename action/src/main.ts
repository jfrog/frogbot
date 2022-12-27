import * as core from '@actions/core';
import {Utils} from './utils';
import {context} from "@actions/github";

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
                await Utils.execCreateFixPullRequests();
                break;
            case "schedule":
                // There are multiple commands with the 'schedule' event, therefore we look at the job name to distinguish between them.
                if (context.job == "scan-pull-requests") {
                    await Utils.execScanPullRequests();
                    break;
                } else if (context.job == "scan-and-fix-repos") {
                    await Utils.execScanAndFixRepos();
                    break;
                }
                core.setFailed("expected scan-pull-requests or scan-and-fix-repos job names, received: " + context.job);
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
