import * as core from '@actions/core';
import { exec } from '@actions/exec';
import { context as githubContext } from '@actions/github';
import { downloadTool, find, cacheFile } from '@actions/tool-cache';
import { chmodSync } from 'fs';
import { platform, arch } from 'os';
import { normalize, join } from 'path';
import { BranchSummary, SimpleGit, simpleGit } from 'simple-git';
import { HttpClient, HttpClientResponse } from '@actions/http-client';
import { OutgoingHttpHeaders } from 'http';

export class Utils {
    private static readonly LATEST_RELEASE_VERSION: string = '[RELEASE]';
    private static readonly LATEST_CLI_VERSION_ARG: string = 'latest';
    private static readonly VERSION_ARG: string = 'version';
    private static readonly TOOL_NAME: string = 'frogbot';
    // OpenID Connect audience input
    private static readonly OIDC_AUDIENCE_ARG: string = 'oidc-audience';
    // OpenID Connect provider_name input
    private static readonly OIDC_INTEGRATION_PROVIDER_NAME_ARG: string = 'oidc-provider-name';

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
        let downloadDir: string = await downloadTool(url, '', auth);
        // Cache 'frogbot' executable
        await this.cacheAndAddPath(downloadDir, version, fileName);
    }

    public static generateAuthString(releasesRepo: string): string {
        if (!releasesRepo) {
            return '';
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

    public static async setFrogbotEnv() {
        core.exportVariable('JF_GIT_PROVIDER', 'github');
        core.exportVariable('JF_GIT_OWNER', githubContext.repo.owner);
        let owner: string | undefined = githubContext.repo.repo;
        if (owner) {
            core.exportVariable('JF_GIT_REPO', owner.substring(owner.indexOf('/') + 1));
        }
        core.exportVariable('JF_GIT_PULL_REQUEST_ID', githubContext.issue.number);

        if (!process.env.JF_GIT_TOKEN) {
            const gitToken: string | undefined = process.env.GITHUB_TOKEN;
            if (!gitToken) {
                throw new Error(
                    'Git token not found. Please ensure GITHUB_TOKEN is available by setting permissions in your workflow, ' +
                    'or set JF_GIT_TOKEN manually.'
                );
            }
            core.exportVariable('JF_GIT_TOKEN', gitToken);
        }

        if (!process.env.JF_GIT_API_ENDPOINT) {
            const apiUrl: string = process.env.GITHUB_API_URL || githubContext.apiUrl || 'https://api.github.com';
            core.exportVariable('JF_GIT_API_ENDPOINT', apiUrl);
        }

        return githubContext.eventName;
    }

    /**
     * Execute frogbot scan-pull-request command.
     */
    public static async execScanPullRequest() {
        if (!process.env.JF_GIT_BASE_BRANCH) {
            core.exportVariable('JF_GIT_BASE_BRANCH', githubContext.ref);
        }
        let res: number = await exec(Utils.getExecutableName(), ['scan-pull-request']);
        if (res !== core.ExitCode.Success) {
            throw new Error('Frogbot exited with exit code ' + res);
        }
    }

    /**
     * Execute frogbot scan-repository command.
     */
    public static async execCreateFixPullRequests() {
        if (!process.env.JF_GIT_BASE_BRANCH) {
            // Get the current branch we are checked on
            const git: SimpleGit = simpleGit();
            try {
                const currentBranch: BranchSummary = await git.branch();
                core.exportVariable('JF_GIT_BASE_BRANCH', currentBranch.current);
            } catch (error) {
                throw new Error('Error getting current branch from the .git folder: ' + error);
            }
        }

        let res: number = await exec(Utils.getExecutableName(), ['scan-repository']);
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
        let execPath: string = find(Utils.TOOL_NAME, version);
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
        let cliDir: string = await cacheFile(downloadDir, fileName, Utils.TOOL_NAME, version);
        if (!Utils.isWindows()) {
            let filePath: string = normalize(join(cliDir, fileName));
            chmodSync(filePath, 0o555);
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
        if (platform().includes('darwin')) {
            if (arch().includes('arm')) {
                return 'mac-arm64';
            }
            return 'mac-386';
        }
        if (arch().includes('arm')) {
            return arch().includes('64') ? 'linux-arm64' : 'linux-arm';
        }
        if (arch().includes('ppc64le')) {
            return 'linux-ppc64le';
        }
        if (arch().includes('ppc64')) {
            return 'linux-ppc64';
        }
        return arch().includes('64') ? 'linux-amd64' : 'linux-386';
    }

    public static getExecutableName() {
        return Utils.isWindows() ? 'frogbot.exe' : 'frogbot';
    }

    public static isWindows() {
        return platform().startsWith('win');
    }
    public static async getJfrogPlatformUrl(): Promise<string> {
        let jfrogUrl: string = process.env.JF_URL ?? '';
        if (!jfrogUrl) {
            throw new Error('JF_URL must be provided and point on your full platform URL, for example: https://mycompany.jfrog.io/');
        }
        return jfrogUrl;
    }

    /**
     * This method will set up an OIDC token if the OIDC integration is set.
     * If OIDC integration is set but not working, the action will fail causing frogbot to fail
     * @param jfrogUrl - The JFrog platform URL
     */
    public static async setupOidcTokenIfNeeded(jfrogUrl: string): Promise<void> {
        const oidcProviderName: string = core.getInput(Utils.OIDC_INTEGRATION_PROVIDER_NAME_ARG);
        if (!oidcProviderName) {
            // No token is set if an oidc-provider-name wasn't provided
            return;
        }
        core.debug('Obtaining an access token through OpenID Connect...');
        const audience: string = core.getInput(Utils.OIDC_AUDIENCE_ARG);
        let jsonWebToken: string | undefined;
        try {
            core.debug('Fetching JSON web token');
            jsonWebToken = await core.getIDToken(audience);
        } catch (error: any) {
            throw new Error(`Getting openID Connect JSON web token failed: ${error.message}`);
        }

        try {
            return await this.initJfrogAccessTokenThroughOidcProtocol(jfrogUrl, jsonWebToken, oidcProviderName);
        } catch (error: any) {
            throw new Error(
                `OIDC authentication against JFrog platform failed, please check OIDC settings and mappings on the JFrog platform: ${error.message}`,
            );
        }
    }

    /**
     * This method exchanges a JSON web token with a JFrog access token through the OpenID Connect protocol
     * If we've reached this stage, the jfrogUrl field should hold a non-empty value obtained from process.env.JF_URL
     * @param jfrogUrl - The JFrog platform URL
     * @param jsonWebToken - The JSON web token used in the token exchange
     * @param oidcProviderName - The OpenID Connect provider name
     */
    private static async initJfrogAccessTokenThroughOidcProtocol(jfrogUrl: string, jsonWebToken: string, oidcProviderName: string): Promise<void> {
        const exchangeUrl: string = jfrogUrl!.replace(/\/$/, '') + '/access/api/v1/oidc/token';

        core.debug('Exchanging GitHub JSON web token with a JFrog access token...');

        const httpClient: HttpClient = new HttpClient();
        const data: string = `{
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
            "subject_token": "${jsonWebToken}",
            "provider_name": "${oidcProviderName}"
        }`;

        const additionalHeaders: OutgoingHttpHeaders = {
            'Content-Type': 'application/json',
        };

        const response: HttpClientResponse = await httpClient.post(exchangeUrl, data, additionalHeaders);
        const responseString: string = await response.readBody();
        const responseJson: TokenExchangeResponseData = JSON.parse(responseString);
        process.env.JF_ACCESS_TOKEN = responseJson.access_token;
        if (responseJson.access_token) {
            core.setSecret(responseJson.access_token);
        }
        if (responseJson.errors) {
            throw new Error(`${JSON.stringify(responseJson.errors)}`);
        }
    }
}
export interface TokenExchangeResponseData {
    access_token: string;
    errors: string;
}
