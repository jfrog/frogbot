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
const github = __importStar(require("@actions/github"));
const toolCache = __importStar(require("@actions/tool-cache"));
const fs = __importStar(require("fs"));
const os = __importStar(require("os"));
const path = __importStar(require("path"));
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
            let downloadDir = yield toolCache.downloadTool(url, '', auth);
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
        core.exportVariable('JF_GIT_PROVIDER', 'github');
        core.exportVariable('JF_GIT_OWNER', github.context.repo.owner);
        let owner = github.context.repo.repo;
        if (owner) {
            core.exportVariable('JF_GIT_REPO', owner.substring(owner.indexOf('/') + 1));
        }
        core.exportVariable('JF_GIT_BASE_BRANCH', github.context.ref);
        core.exportVariable('JF_GIT_PULL_REQUEST_ID', github.context.issue.number);
        return github.context.eventName;
    }
    /**
     * Execute frogbot scan-pull-request command.
     */
    static execScanPullRequest() {
        return __awaiter(this, void 0, void 0, function* () {
            let res = yield (0, exec_1.exec)(Utils.getExecutableName(), ['scan-pull-request']);
            if (res !== core.ExitCode.Success) {
                throw new Error('Frogbot exited with exit code ' + res);
            }
        });
    }
    /**
     * Execute frogbot create-fix-pull-requests command.
     */
    static execCreateFixPullRequests() {
        return __awaiter(this, void 0, void 0, function* () {
            let res = yield (0, exec_1.exec)(Utils.getExecutableName(), ['create-fix-pull-requests']);
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
        let execPath = toolCache.find(Utils.TOOL_NAME, version);
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
            let cliDir = yield toolCache.cacheFile(downloadDir, fileName, Utils.TOOL_NAME, version);
            if (!Utils.isWindows()) {
                fs.chmodSync(path.join(cliDir, fileName), 0o555);
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
    static getExecutableName() {
        return Utils.isWindows() ? 'frogbot.exe' : 'frogbot';
    }
    static isWindows() {
        return os.platform().startsWith('win');
    }
}
exports.Utils = Utils;
Utils.LATEST_RELEASE_VERSION = '[RELEASE]';
Utils.LATEST_CLI_VERSION_ARG = 'latest';
Utils.VERSION_ARG = 'version';
Utils.TOOL_NAME = 'frogbot';
