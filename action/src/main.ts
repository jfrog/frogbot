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
                if (context.job == "scan-pull-requests") {
                    await Utils.execScanPullRequests();
                    break;
                }
                await Utils.execScanAndFixRepos();
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
