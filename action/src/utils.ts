import * as core from '@actions/core';
import { exec } from '@actions/exec';
import * as github from '@actions/github';
import * as toolCache from '@actions/tool-cache';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

export class Utils {
    private static readonly LATEST_RELEASE_VERSION: string = '[RELEASE]';
    private static readonly LATEST_CLI_VERSION_ARG: string = 'latest';
    private static readonly VERSION_ARG: string = 'version';
    private static readonly TOOL_NAME: string = 'frogbot';

    public static async addToPath() {
        let fileName: string = Utils.getExecutableName();
        let version: string = core.getInput(Utils.VERSION_ARG);
        let major: string = version.split('.')[0];
        if (version === this.LATEST_CLI_VERSION_ARG) {
            version = Utils.LATEST_RELEASE_VERSION;
            major = '2';
        } else {
            if (this.loadFromCache(version)) {
                // Download is not needed
                return;
            }
        }

        // Download Frogbot
        const releasesRepo: string = process.env.JF_RELEASES_REPO ?? '';
        let url: string = Utils.getCliUrl(major, version, fileName, releasesRepo);
        core.debug('Downloading Frogbot from ' + url);
        let auth: string = this.generateAuthString(releasesRepo);
        let downloadDir: string = await toolCache.downloadTool(url, '', auth);
        // Cache 'frogbot' executable
        await this.cacheAndAddPath(downloadDir, version, fileName);
    }

    public static generateAuthString(releasesRepo: string): string {
        if (!releasesRepo) {
            return ''
        }
        let accessToken: string = process.env.JF_ACCESS_TOKEN ?? '';
        let username: string = process.env.JF_USER ?? '';
        let password: string = process.env.JF_PASSWORD ?? '';
        if (accessToken) {
            return 'Bearer ' + Buffer.from(accessToken).toString();
        } else if (username && password) {
            return 'Basic ' + Buffer.from(username + ':' + password).toString('base64');
        }
        return '';
    }

    public static setFrogbotEnv() {
        core.exportVariable('JF_GIT_PROVIDER', 'github');
        core.exportVariable('JF_GIT_OWNER', github.context.repo.owner);
        let owner: string | undefined = github.context.repo.repo;
        if (owner) {
            core.exportVariable('JF_GIT_REPO', owner.substring(owner.indexOf('/') + 1));
        }
        core.exportVariable('JF_GIT_BASE_BRANCH', github.context.ref);
        core.exportVariable('JF_GIT_PULL_REQUEST_ID', github.context.issue.number);
        return github.context.eventName
    }

    /**
     * Execute frogbot scan-pull-request command.
     */
    public static async execScanPullRequest() {
        let res: number = await exec(Utils.getExecutableName(), ['scan-pull-request']);
        if (res !== core.ExitCode.Success) {
            throw new Error('Frogbot exited with exit code ' + res);
        }
    }

    /**
     * Execute frogbot create-fix-pull-requests command.
     */
    public static async execCreateFixPullRequests() {
        let res: number = await exec(Utils.getExecutableName(), ['create-fix-pull-requests']);
        if (res !== core.ExitCode.Success) {
            throw new Error('Frogbot exited with exit code ' + res);
        }
    }

    /**
     * Try to load the Frogbot executables from cache.
     *
     * @param version  - Frogbot version
     * @returns true if the CLI executable was loaded from cache and added to path
     */
    private static loadFromCache(version: string): boolean {
        let execPath: string = toolCache.find(Utils.TOOL_NAME, version);
        if (execPath) {
            core.addPath(execPath);
            return true;
        }
        return false;
    }

    /**
     * Add Frogbot executable to cache and to the system path.
     * @param downloadDir - The directory whereby the CLI was downloaded to
     * @param version     - Frogbot version
     * @param fileName    - 'frogbot' or 'frogbot.exe'
     */
    private static async cacheAndAddPath(downloadDir: string, version: string, fileName: string) {
        let cliDir: string = await toolCache.cacheFile(downloadDir, fileName, Utils.TOOL_NAME, version);
        if (!Utils.isWindows()) {
            fs.chmodSync(path.join(cliDir, fileName), 0o555);
        }
        core.addPath(cliDir);
    }

    public static getCliUrl(major: string, version: string, fileName: string, releasesRepo: string): string {
        let architecture: string = 'frogbot-' + Utils.getArchitecture();
        if (releasesRepo) {
            let platformUrl: string = process.env.JF_URL ?? '';
            if (!platformUrl) {
                throw new Error('Failed while downloading Frogbot from Artifactory, JF_URL must be set');
            }
            // Remove trailing slash if exists
            platformUrl = platformUrl.replace(/\/$/, '');
            return `${platformUrl}/artifactory/${releasesRepo}/artifactory/frogbot/v${major}/${version}/${architecture}/${fileName}`;
        }
        return `https://releases.jfrog.io/artifactory/frogbot/v${major}/${version}/${architecture}/${fileName}`;
    }

    public static getArchitecture() {
        if (Utils.isWindows()) {
            return 'windows-amd64';
        }
        if (os.platform().includes('darwin')) {
            return 'mac-386';
        }
        if (os.arch().includes('arm')) {
            return os.arch().includes('64') ? 'linux-arm64' : 'linux-arm';
        }
        if (os.arch().includes('ppc64le')) {
            return 'linux-ppc64le';
        }
        if (os.arch().includes('ppc64')) {
            return 'linux-ppc64';
        }
        return os.arch().includes('64') ? 'linux-amd64' : 'linux-386';
    }

    public static getExecutableName() {
        return Utils.isWindows() ? 'frogbot.exe' : 'frogbot';
    }

    public static isWindows() {
        return os.platform().startsWith('win');
    }
}
