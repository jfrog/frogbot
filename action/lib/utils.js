"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Utils = void 0;
const core = __importStar(require("@actions/core"));
const exec_1 = require("@actions/exec");
const github_1 = require("@actions/github");
const tool_cache_1 = require("@actions/tool-cache");
const fs_1 = require("fs");
const os_1 = require("os");
const path_1 = require("path");
const simple_git_1 = require("simple-git");
const http_client_1 = require("@actions/http-client");
class Utils {
    static addToPath() {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            let fileName = Utils.getExecutableName();
            let version = core.getInput(Utils.VERSION_ARG);
            let major = version.split('.')[0];
            if (version === this.LATEST_CLI_VERSION_ARG) {
                version = Utils.LATEST_RELEASE_VERSION;
                major = '2';
            }
            else {
                if (this.loadFromCache(version)) {
                    // Download is not needed
                    return;
                }
            }
            // Download Frogbot
            const releasesRepo = (_a = process.env.JF_RELEASES_REPO) !== null && _a !== void 0 ? _a : '';
            let url = Utils.getCliUrl(major, version, fileName, releasesRepo);
            core.debug('Downloading Frogbot from ' + url);
            let auth = this.generateAuthString(releasesRepo);
            let downloadDir = yield (0, tool_cache_1.downloadTool)(url, '', auth);
            // Cache 'frogbot' executable
            yield this.cacheAndAddPath(downloadDir, version, fileName);
        });
    }
    static generateAuthString(releasesRepo) {
        var _a, _b, _c;
        if (!releasesRepo) {
            return '';
        }
        let accessToken = (_a = process.env.JF_ACCESS_TOKEN) !== null && _a !== void 0 ? _a : '';
        let username = (_b = process.env.JF_USER) !== null && _b !== void 0 ? _b : '';
        let password = (_c = process.env.JF_PASSWORD) !== null && _c !== void 0 ? _c : '';
        if (accessToken) {
            return 'Bearer ' + Buffer.from(accessToken).toString();
        }
        else if (username && password) {
            return 'Basic ' + Buffer.from(username + ':' + password).toString('base64');
        }
        return '';
    }
    static setFrogbotEnv() {
        return __awaiter(this, void 0, void 0, function* () {
            core.exportVariable('JF_GIT_PROVIDER', 'github');
            core.exportVariable('JF_GIT_OWNER', github_1.context.repo.owner);
            let owner = github_1.context.repo.repo;
            if (owner) {
                core.exportVariable('JF_GIT_REPO', owner.substring(owner.indexOf('/') + 1));
            }
            core.exportVariable('JF_GIT_PULL_REQUEST_ID', github_1.context.issue.number);
            return github_1.context.eventName;
        });
    }
    /**
     * Execute frogbot scan-pull-request command.
     */
    static execScanPullRequest() {
        return __awaiter(this, void 0, void 0, function* () {
            if (!process.env.JF_GIT_BASE_BRANCH) {
                core.exportVariable('JF_GIT_BASE_BRANCH', github_1.context.ref);
            }
            let res = yield (0, exec_1.exec)(Utils.getExecutableName(), ['scan-pull-request']);
            if (res !== core.ExitCode.Success) {
                throw new Error('Frogbot exited with exit code ' + res);
            }
        });
    }
    /**
     * Execute frogbot scan-repository command.
     */
    static execCreateFixPullRequests() {
        return __awaiter(this, void 0, void 0, function* () {
            if (!process.env.JF_GIT_BASE_BRANCH) {
                // Get the current branch we are checked on
                const git = (0, simple_git_1.simpleGit)();
                try {
                    const currentBranch = yield git.branch();
                    core.exportVariable('JF_GIT_BASE_BRANCH', currentBranch.current);
                }
                catch (error) {
                    throw new Error('Error getting current branch from the .git folder: ' + error);
                }
            }
            let res = yield (0, exec_1.exec)(Utils.getExecutableName(), ['scan-repository']);
            if (res !== core.ExitCode.Success) {
                throw new Error('Frogbot exited with exit code ' + res);
            }
        });
    }
    /**
     * Try to load the Frogbot executables from cache.
     *
     * @param version  - Frogbot version
     * @returns true if the CLI executable was loaded from cache and added to path
     */
    static loadFromCache(version) {
        let execPath = (0, tool_cache_1.find)(Utils.TOOL_NAME, version);
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
    static cacheAndAddPath(downloadDir, version, fileName) {
        return __awaiter(this, void 0, void 0, function* () {
            let cliDir = yield (0, tool_cache_1.cacheFile)(downloadDir, fileName, Utils.TOOL_NAME, version);
            if (!Utils.isWindows()) {
                let filePath = (0, path_1.normalize)((0, path_1.join)(cliDir, fileName));
                (0, fs_1.chmodSync)(filePath, 0o555);
            }
            core.addPath(cliDir);
        });
    }
    static getCliUrl(major, version, fileName, releasesRepo) {
        var _a;
        let architecture = 'frogbot-' + Utils.getArchitecture();
        if (releasesRepo) {
            let platformUrl = (_a = process.env.JF_URL) !== null && _a !== void 0 ? _a : '';
            if (!platformUrl) {
                throw new Error('Failed while downloading Frogbot from Artifactory, JF_URL must be set');
            }
            // Remove trailing slash if exists
            platformUrl = platformUrl.replace(/\/$/, '');
            return `${platformUrl}/artifactory/${releasesRepo}/artifactory/frogbot/v${major}/${version}/${architecture}/${fileName}`;
        }
        return `https://releases.jfrog.io/artifactory/frogbot/v${major}/${version}/${architecture}/${fileName}`;
    }
    static getArchitecture() {
        if (Utils.isWindows()) {
            return 'windows-amd64';
        }
        if ((0, os_1.platform)().includes('darwin')) {
            if ((0, os_1.arch)().includes('arm')) {
                return (0, os_1.arch)().includes('64') ? 'mac-arm64' : 'mac-arm';
            }
            return 'mac-386';
        }
        if ((0, os_1.arch)().includes('arm')) {
            return (0, os_1.arch)().includes('64') ? 'linux-arm64' : 'linux-arm';
        }
        if ((0, os_1.arch)().includes('ppc64le')) {
            return 'linux-ppc64le';
        }
        if ((0, os_1.arch)().includes('ppc64')) {
            return 'linux-ppc64';
        }
        return (0, os_1.arch)().includes('64') ? 'linux-amd64' : 'linux-386';
    }
    static getExecutableName() {
        return Utils.isWindows() ? 'frogbot.exe' : 'frogbot';
    }
    static isWindows() {
        return (0, os_1.platform)().startsWith('win');
    }
    static getJfrogPlatformUrl() {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            let jfrogUrl = (_a = process.env.JF_URL) !== null && _a !== void 0 ? _a : '';
            if (!jfrogUrl) {
                throw new Error('JF_URL must be provided and point on your full platform URL, for example: https://mycompany.jfrog.io/');
            }
            return jfrogUrl;
        });
    }
    /**
     * This method will set up an OIDC token if the OIDC integration is set.
     * If OIDC integration is set but not working, the action will fail causing frogbot to fail
     * @param jfrogUrl - The JFrog platform URL
     */
    static setupOidcTokenIfNeeded(jfrogUrl) {
        return __awaiter(this, void 0, void 0, function* () {
            const oidcProviderName = core.getInput(Utils.OIDC_INTEGRATION_PROVIDER_NAME_ARG);
            if (!oidcProviderName) {
                // No token is set if an oidc-provider-name wasn't provided
                return;
            }
            core.debug('Obtaining an access token through OpenID Connect...');
            const audience = core.getInput(Utils.OIDC_AUDIENCE_ARG);
            let jsonWebToken;
            try {
                core.debug('Fetching JSON web token');
                jsonWebToken = yield core.getIDToken(audience);
            }
            catch (error) {
                throw new Error(`Getting openID Connect JSON web token failed: ${error.message}`);
            }
            try {
                return yield this.initJfrogAccessTokenThroughOidcProtocol(jfrogUrl, jsonWebToken, oidcProviderName);
            }
            catch (error) {
                throw new Error(`OIDC authentication against JFrog platform failed, please check OIDC settings and mappings on the JFrog platform: ${error.message}`);
            }
        });
    }
    /**
     * This method exchanges a JSON web token with a JFrog access token through the OpenID Connect protocol
     * If we've reached this stage, the jfrogUrl field should hold a non-empty value obtained from process.env.JF_URL
     * @param jfrogUrl - The JFrog platform URL
     * @param jsonWebToken - The JSON web token used in the token exchange
     * @param oidcProviderName - The OpenID Connect provider name
     */
    static initJfrogAccessTokenThroughOidcProtocol(jfrogUrl, jsonWebToken, oidcProviderName) {
        return __awaiter(this, void 0, void 0, function* () {
            const exchangeUrl = jfrogUrl.replace(/\/$/, '') + '/access/api/v1/oidc/token';
            core.debug('Exchanging GitHub JSON web token with a JFrog access token...');
            const httpClient = new http_client_1.HttpClient();
            const data = `{
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
            "subject_token": "${jsonWebToken}",
            "provider_name": "${oidcProviderName}"
        }`;
            const additionalHeaders = {
                'Content-Type': 'application/json',
            };
            const response = yield httpClient.post(exchangeUrl, data, additionalHeaders);
            const responseString = yield response.readBody();
            const responseJson = JSON.parse(responseString);
            process.env.JF_ACCESS_TOKEN = responseJson.access_token;
            if (responseJson.access_token) {
                core.setSecret(responseJson.access_token);
            }
            if (responseJson.errors) {
                throw new Error(`${JSON.stringify(responseJson.errors)}`);
            }
        });
    }
}
exports.Utils = Utils;
Utils.LATEST_RELEASE_VERSION = '[RELEASE]';
Utils.LATEST_CLI_VERSION_ARG = 'latest';
Utils.VERSION_ARG = 'version';
Utils.TOOL_NAME = 'frogbot';
// OpenID Connect audience input
Utils.OIDC_AUDIENCE_ARG = 'oidc-audience';
// OpenID Connect provider_name input
Utils.OIDC_INTEGRATION_PROVIDER_NAME_ARG = 'oidc-provider-name';
