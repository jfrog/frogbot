"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const os_1 = __importDefault(require("os"));
const fs_1 = require("fs");
const path_1 = require("path");
const tool_cache_1 = require("@actions/tool-cache");
const checksum_1 = require("../src/checksum");
const utils_1 = require("../src/utils");
jest.mock('os');
jest.mock('@actions/tool-cache');
jest.mock('../src/checksum');
describe('Frogbot Action Tests', () => {
    afterEach(() => {
        delete process.env.JF_ACCESS_TOKEN;
        delete process.env.JF_USER;
        delete process.env.JF_PASSWORD;
        delete process.env.JF_GIT_PROVIDER;
        delete process.env.JF_GIT_OWNER;
        delete process.env.GITHUB_REPOSITORY_OWNER;
        delete process.env.GITHUB_REPOSITORY;
        delete process.env.GITHUB_TOKEN;
        delete process.env.JF_GIT_TOKEN;
        delete process.env.JF_GIT_API_ENDPOINT;
        delete process.env.GITHUB_API_URL;
        delete process.env.JF_GIT_SERVER_URL;
        delete process.env.GITHUB_SERVER_URL;
    });
    describe('Auto-PR action contract', () => {
        const repositoryRoot = (0, path_1.join)(__dirname, '..', '..');
        it('Declares the Auto-PR inputs in the root action manifest', () => {
            const manifest = (0, fs_1.readFileSync)((0, path_1.join)(repositoryRoot, 'action.yml'), 'utf8');
            expect(manifest).toContain('command:');
            expect(manifest).toContain('component-name:');
            expect(manifest).toContain('affected-version:');
            expect(manifest).toContain('fix-version:');
            expect(manifest).toContain('branch-name:');
            expect(manifest).toContain('commit-hash:');
            expect(manifest).toContain('main: "action/lib/main.js"');
        });
        it('Passes the repository default branch when branch-name is omitted', () => {
            const workflow = (0, fs_1.readFileSync)((0, path_1.join)(repositoryRoot, '.github', 'workflows', 'frogbot-auto-pr.yml'), 'utf8');
            expect(workflow).toContain('branch-name: ${{ inputs.branch-name || github.event.repository.default_branch }}');
        });
        it('Invokes the local Auto-PR action in CI', () => {
            const workflow = (0, fs_1.readFileSync)((0, path_1.join)(repositoryRoot, '.github', 'workflows', 'action-test.yml'), 'utf8');
            expect(workflow).toContain('uses: ./');
        });
    });
    describe('Frogbot URL Tests', () => {
        const myOs = os_1.default;
        const cases = [
            ['win32', 'amd64', 'jfrog.exe', 'https://releases.jfrog.io/artifactory/frogbot/v1/1.2.3/frogbot-windows-amd64/jfrog.exe'],
            ['darwin', 'amd64', 'jfrog', 'https://releases.jfrog.io/artifactory/frogbot/v1/1.2.3/frogbot-mac-386/jfrog'],
            ['darwin', 'arm64', 'jfrog', 'https://releases.jfrog.io/artifactory/frogbot/v1/1.2.3/frogbot-mac-arm64/jfrog'],
            ['linux', 'amd64', 'jfrog', 'https://releases.jfrog.io/artifactory/frogbot/v1/1.2.3/frogbot-linux-amd64/jfrog'],
            ['linux', 'arm64', 'jfrog', 'https://releases.jfrog.io/artifactory/frogbot/v1/1.2.3/frogbot-linux-arm64/jfrog'],
            ['linux', '386', 'jfrog', 'https://releases.jfrog.io/artifactory/frogbot/v1/1.2.3/frogbot-linux-386/jfrog'],
            ['linux', 'arm', 'jfrog', 'https://releases.jfrog.io/artifactory/frogbot/v1/1.2.3/frogbot-linux-arm/jfrog'],
            ['linux', 'ppc64', 'jfrog', 'https://releases.jfrog.io/artifactory/frogbot/v1/1.2.3/frogbot-linux-ppc64/jfrog'],
            ['linux', 'ppc64le', 'jfrog', 'https://releases.jfrog.io/artifactory/frogbot/v1/1.2.3/frogbot-linux-ppc64le/jfrog'],
        ];
        test.each(cases)('CLI Url for %s-%s', (platform, arch, fileName, expectedUrl) => {
            myOs.platform.mockImplementation(() => platform);
            myOs.arch.mockImplementation(() => arch);
            expect(utils_1.Utils.getCliUrl('1', '1.2.3', fileName, '')).toBe(expectedUrl);
        });
    });
    describe('Frogbot URL Tests With Remote Artifactory', () => {
        const myOs = os_1.default;
        const releasesRepo = 'frogbot-remote';
        const cases = [
            ['win32', 'amd64', 'jfrog.exe', 'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.8.7/frogbot-windows-amd64/jfrog.exe'],
            ['darwin', 'amd64', 'jfrog', 'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.8.7/frogbot-mac-386/jfrog'],
            ['darwin', 'arm64', 'jfrog', 'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.8.7/frogbot-mac-arm64/jfrog'],
            ['linux', 'amd64', 'jfrog', 'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.8.7/frogbot-linux-amd64/jfrog'],
            ['linux', 'arm64', 'jfrog', 'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.8.7/frogbot-linux-arm64/jfrog'],
            ['linux', '386', 'jfrog', 'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.8.7/frogbot-linux-386/jfrog'],
            ['linux', 'arm', 'jfrog', 'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.8.7/frogbot-linux-arm/jfrog'],
            ['linux', 'ppc64', 'jfrog', 'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.8.7/frogbot-linux-ppc64/jfrog'],
            ['linux', 'ppc64le', 'jfrog', 'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.8.7/frogbot-linux-ppc64le/jfrog'],
        ];
        beforeEach(() => {
            process.env.JF_URL = 'https://myfrogbot.com/';
        });
        afterEach(() => {
            delete process.env.JF_URL;
        });
        test.each(cases)('Remote CLI Url for %s-%s', (platform, arch, fileName, expectedUrl) => {
            myOs.platform.mockImplementation(() => platform);
            myOs.arch.mockImplementation(() => arch);
            expect(utils_1.Utils.getCliUrl('2', '2.8.7', fileName, releasesRepo)).toBe(expectedUrl);
        });
    });
    describe('Generate auth string', () => {
        it('Should return an empty string if releasesRepo is falsy', () => {
            const result = utils_1.Utils.generateAuthString('');
            expect(result).toBe('');
        });
        it('Should generate a Bearer token if accessToken is provided', () => {
            process.env.JF_ACCESS_TOKEN = 'yourAccessToken';
            const result = utils_1.Utils.generateAuthString('yourReleasesRepo');
            expect(result).toBe('Bearer yourAccessToken');
        });
        it('Should generate a Basic token if username and password are provided', () => {
            process.env.JF_USER = 'yourUsername';
            process.env.JF_PASSWORD = 'yourPassword';
            const result = utils_1.Utils.generateAuthString('yourReleasesRepo');
            expect(result).toBe('Basic eW91clVzZXJuYW1lOnlvdXJQYXNzd29yZA==');
        });
        it('Should return an empty string if no credentials are provided', () => {
            const result = utils_1.Utils.generateAuthString('yourReleasesRepo');
            expect(result).toBe('');
        });
    });
    it('Repository env tests', () => __awaiter(void 0, void 0, void 0, function* () {
        process.env['GITHUB_REPOSITORY_OWNER'] = 'jfrog';
        process.env['GITHUB_REPOSITORY'] = 'jfrog/frogbot';
        process.env['GITHUB_TOKEN'] = 'ghp_test_token';
        yield utils_1.Utils.setFrogbotEnv();
        expect(process.env['JF_GIT_PROVIDER']).toBe('github');
        expect(process.env['JF_GIT_OWNER']).toBe('jfrog');
    }));
    describe('Auto-detect Git token', () => {
        afterEach(() => {
            delete process.env.JF_GIT_TOKEN;
            delete process.env.GITHUB_TOKEN;
            delete process.env.GITHUB_REPOSITORY_OWNER;
            delete process.env.GITHUB_REPOSITORY;
        });
        it('Should auto-detect JF_GIT_TOKEN from GITHUB_TOKEN', () => __awaiter(void 0, void 0, void 0, function* () {
            process.env['GITHUB_TOKEN'] = 'ghp_test_token_123';
            process.env['GITHUB_REPOSITORY_OWNER'] = 'jfrog';
            process.env['GITHUB_REPOSITORY'] = 'jfrog/frogbot';
            yield utils_1.Utils.setFrogbotEnv();
            expect(process.env['JF_GIT_TOKEN']).toBe('ghp_test_token_123');
        }));
        it('Should use existing JF_GIT_TOKEN if already set', () => __awaiter(void 0, void 0, void 0, function* () {
            process.env['JF_GIT_TOKEN'] = 'custom_token_456';
            process.env['GITHUB_TOKEN'] = 'ghp_test_token_123';
            process.env['GITHUB_REPOSITORY_OWNER'] = 'jfrog';
            process.env['GITHUB_REPOSITORY'] = 'jfrog/frogbot';
            yield utils_1.Utils.setFrogbotEnv();
            expect(process.env['JF_GIT_TOKEN']).toBe('custom_token_456');
        }));
        it('Should throw error if no token is available', () => __awaiter(void 0, void 0, void 0, function* () {
            process.env['GITHUB_REPOSITORY_OWNER'] = 'jfrog';
            process.env['GITHUB_REPOSITORY'] = 'jfrog/frogbot';
            yield expect(utils_1.Utils.setFrogbotEnv()).rejects.toThrow('Git token not found');
        }));
    });
    describe('Auto-detect API endpoint', () => {
        afterEach(() => {
            delete process.env.JF_GIT_API_ENDPOINT;
            delete process.env.GITHUB_API_URL;
            delete process.env.GITHUB_TOKEN;
            delete process.env.GITHUB_REPOSITORY_OWNER;
            delete process.env.GITHUB_REPOSITORY;
        });
        it('Should auto-detect JF_GIT_API_ENDPOINT from GITHUB_API_URL', () => __awaiter(void 0, void 0, void 0, function* () {
            process.env['GITHUB_API_URL'] = 'https://api.github.enterprise.com';
            process.env['GITHUB_TOKEN'] = 'ghp_test_token';
            process.env['GITHUB_REPOSITORY_OWNER'] = 'jfrog';
            process.env['GITHUB_REPOSITORY'] = 'jfrog/frogbot';
            yield utils_1.Utils.setFrogbotEnv();
            expect(process.env['JF_GIT_API_ENDPOINT']).toBe('https://api.github.enterprise.com');
        }));
        it('Should use default API endpoint if GITHUB_API_URL not set', () => __awaiter(void 0, void 0, void 0, function* () {
            process.env['GITHUB_TOKEN'] = 'ghp_test_token';
            process.env['GITHUB_REPOSITORY_OWNER'] = 'jfrog';
            process.env['GITHUB_REPOSITORY'] = 'jfrog/frogbot';
            yield utils_1.Utils.setFrogbotEnv();
            expect(process.env['JF_GIT_API_ENDPOINT']).toBe('https://api.github.com');
        }));
        it('Should use existing JF_GIT_API_ENDPOINT if already set', () => __awaiter(void 0, void 0, void 0, function* () {
            process.env['JF_GIT_API_ENDPOINT'] = 'https://custom.api.com';
            process.env['GITHUB_API_URL'] = 'https://api.github.enterprise.com';
            process.env['GITHUB_TOKEN'] = 'ghp_test_token';
            process.env['GITHUB_REPOSITORY_OWNER'] = 'jfrog';
            process.env['GITHUB_REPOSITORY'] = 'jfrog/frogbot';
            yield utils_1.Utils.setFrogbotEnv();
            expect(process.env['JF_GIT_API_ENDPOINT']).toBe('https://custom.api.com');
        }));
    });
    describe('Auto-detect server URL', () => {
        afterEach(() => {
            delete process.env.JF_GIT_SERVER_URL;
            delete process.env.GITHUB_SERVER_URL;
            delete process.env.GITHUB_TOKEN;
            delete process.env.GITHUB_REPOSITORY_OWNER;
            delete process.env.GITHUB_REPOSITORY;
        });
        it('Should auto-detect JF_GIT_SERVER_URL from GITHUB_SERVER_URL', () => __awaiter(void 0, void 0, void 0, function* () {
            process.env['GITHUB_SERVER_URL'] = 'https://myenterprise.github.com';
            process.env['GITHUB_TOKEN'] = 'ghp_test_token';
            process.env['GITHUB_REPOSITORY_OWNER'] = 'jfrog';
            process.env['GITHUB_REPOSITORY'] = 'jfrog/frogbot';
            yield utils_1.Utils.setFrogbotEnv();
            expect(process.env['JF_GIT_SERVER_URL']).toBe('https://myenterprise.github.com');
        }));
        it('Should default JF_GIT_SERVER_URL to https://github.com if GITHUB_SERVER_URL not set', () => __awaiter(void 0, void 0, void 0, function* () {
            process.env['GITHUB_TOKEN'] = 'ghp_test_token';
            process.env['GITHUB_REPOSITORY_OWNER'] = 'jfrog';
            process.env['GITHUB_REPOSITORY'] = 'jfrog/frogbot';
            yield utils_1.Utils.setFrogbotEnv();
            expect(process.env['JF_GIT_SERVER_URL']).toBe('https://github.com');
        }));
        it('Should use existing JF_GIT_SERVER_URL if already set', () => __awaiter(void 0, void 0, void 0, function* () {
            process.env['JF_GIT_SERVER_URL'] = 'https://custom.server.com';
            process.env['GITHUB_SERVER_URL'] = 'https://myenterprise.github.com';
            process.env['GITHUB_TOKEN'] = 'ghp_test_token';
            process.env['GITHUB_REPOSITORY_OWNER'] = 'jfrog';
            process.env['GITHUB_REPOSITORY'] = 'jfrog/frogbot';
            yield utils_1.Utils.setFrogbotEnv();
            expect(process.env['JF_GIT_SERVER_URL']).toBe('https://custom.server.com');
        }));
    });
    describe('Frogbot download', () => {
        let cacheDir;
        let binaryPath;
        beforeEach(() => {
            os_1.default.platform.mockReturnValue('linux');
            os_1.default.arch.mockReturnValue('x64');
            const realTmp = jest.requireActual('os').tmpdir();
            cacheDir = (0, fs_1.mkdtempSync)((0, path_1.join)(realTmp, 'frogbot-cache-'));
            binaryPath = (0, path_1.join)(cacheDir, 'frogbot');
            (0, fs_1.writeFileSync)(binaryPath, 'binary');
            tool_cache_1.find.mockReturnValue('');
            tool_cache_1.downloadTool.mockResolvedValue(binaryPath);
            checksum_1.verifyDownloadedFile.mockResolvedValue(undefined);
            tool_cache_1.cacheFile.mockResolvedValue(cacheDir);
            process.env.INPUT_VERSION = '3.7.0';
        });
        afterEach(() => {
            (0, fs_1.rmSync)(cacheDir, { recursive: true, force: true });
            delete process.env.INPUT_VERSION;
            delete process.env.JF_RELEASES_REPO;
            delete process.env.JF_URL;
            delete process.env.JF_ACCESS_TOKEN;
            jest.clearAllMocks();
        });
        it('Verifies the downloaded Frogbot binary before caching it', () => __awaiter(void 0, void 0, void 0, function* () {
            yield utils_1.Utils.addToPath();
            const cliUrl = 'https://releases.jfrog.io/artifactory/frogbot/v3/3.7.0/frogbot-linux-amd64/frogbot';
            expect(tool_cache_1.downloadTool).toHaveBeenCalledWith(cliUrl, '', '');
            expect(checksum_1.verifyDownloadedFile).toHaveBeenCalledWith(binaryPath, cliUrl, '');
            const verifyOrder = checksum_1.verifyDownloadedFile.mock.invocationCallOrder[0];
            const cacheOrder = tool_cache_1.cacheFile.mock.invocationCallOrder[0];
            expect(verifyOrder).toBeLessThan(cacheOrder);
        }));
        it('Does not cache Frogbot when checksum verification fails', () => __awaiter(void 0, void 0, void 0, function* () {
            checksum_1.verifyDownloadedFile.mockRejectedValue(new Error('Checksum verification failed'));
            yield expect(utils_1.Utils.addToPath()).rejects.toThrow('Checksum verification failed');
            expect(tool_cache_1.cacheFile).not.toHaveBeenCalled();
        }));
        it('Downloads the v2 binary when the version input is a v2 release', () => __awaiter(void 0, void 0, void 0, function* () {
            process.env.INPUT_VERSION = '2.35.3';
            yield utils_1.Utils.addToPath();
            expect(tool_cache_1.downloadTool).toHaveBeenCalledWith('https://releases.jfrog.io/artifactory/frogbot/v2/2.35.3/frogbot-linux-amd64/frogbot', '', '');
        }));
        it('Downloads the v3 latest binary without using the tool cache', () => __awaiter(void 0, void 0, void 0, function* () {
            process.env.INPUT_VERSION = 'latest';
            yield utils_1.Utils.addToPath();
            expect(tool_cache_1.find).not.toHaveBeenCalled();
            expect(tool_cache_1.downloadTool).toHaveBeenCalledWith('https://releases.jfrog.io/artifactory/frogbot/v3/[RELEASE]/frogbot-linux-amd64/frogbot', '', '');
        }));
        it('Passes releases-repo credentials when verifying Frogbot', () => __awaiter(void 0, void 0, void 0, function* () {
            process.env.JF_RELEASES_REPO = 'frogbot-remote';
            process.env.JF_URL = 'https://myfrogbot.com/';
            process.env.JF_ACCESS_TOKEN = 'token';
            yield utils_1.Utils.addToPath();
            const cliUrl = 'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v3/3.7.0/frogbot-linux-amd64/frogbot';
            expect(tool_cache_1.downloadTool).toHaveBeenCalledWith(cliUrl, '', 'Bearer token');
            expect(checksum_1.verifyDownloadedFile).toHaveBeenCalledWith(binaryPath, cliUrl, 'Bearer token');
        }));
        it('Skips the download when the pinned version is already cached', () => __awaiter(void 0, void 0, void 0, function* () {
            tool_cache_1.find.mockReturnValue(cacheDir);
            yield utils_1.Utils.addToPath();
            expect(tool_cache_1.downloadTool).not.toHaveBeenCalled();
            expect(checksum_1.verifyDownloadedFile).not.toHaveBeenCalled();
            expect(tool_cache_1.cacheFile).not.toHaveBeenCalled();
        }));
    });
});
