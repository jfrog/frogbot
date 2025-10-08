"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const os_1 = __importDefault(require("os"));
const utils_1 = require("../src/utils");
jest.mock('os');
describe('Frogbot Action Tests', () => {
    afterEach(() => {
        delete process.env.JF_ACCESS_TOKEN;
        delete process.env.JF_USER;
        delete process.env.PASSWORD;
        delete process.env.JF_GIT_PROVIDER;
        delete process.env.JF_GIT_OWNER;
        delete process.env.GITHUB_REPOSITORY_OWNER;
        delete process.env.GITHUB_REPOSITORY;
    });
    describe('Frogbot URL Tests', () => {
        const myOs = os_1.default;
        let cases = [
            [
                'win32',
                'amd64',
                'jfrog.exe',
                'https://releases.jfrog.io/artifactory/frogbot/v1/1.2.3/frogbot-windows-amd64/jfrog.exe',
            ],
            ['darwin', 'amd64', 'jfrog', 'https://releases.jfrog.io/artifactory/frogbot/v1/1.2.3/frogbot-mac-386/jfrog'],
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
            let cliUrl = utils_1.Utils.getCliUrl('1', '1.2.3', fileName, '');
            expect(cliUrl).toBe(expectedUrl);
        });
    });
    describe('Frogbot URL Tests With Remote Artifactory', () => {
        const myOs = os_1.default;
        const releasesRepo = 'frogbot-remote';
        process.env['JF_URL'] = 'https://myfrogbot.com/';
        process.env['JF_ACCESS_TOKEN'] = 'access_token1';
        let cases = [
            [
                'win32',
                'amd64',
                'jfrog.exe',
                'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.8.7/frogbot-windows-amd64/jfrog.exe',
            ],
            [
                'darwin',
                'amd64',
                'jfrog',
                'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.8.7/frogbot-mac-386/jfrog',
            ],
            [
                'linux',
                'amd64',
                'jfrog',
                'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.8.7/frogbot-linux-amd64/jfrog',
            ],
            [
                'linux',
                'arm64',
                'jfrog',
                'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.8.7/frogbot-linux-arm64/jfrog',
            ],
            [
                'linux',
                '386',
                'jfrog',
                'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.8.7/frogbot-linux-386/jfrog',
            ],
            [
                'linux',
                'arm',
                'jfrog',
                'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.8.7/frogbot-linux-arm/jfrog',
            ],
            [
                'linux',
                'ppc64',
                'jfrog',
                'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.8.7/frogbot-linux-ppc64/jfrog',
            ],
            [
                'linux',
                'ppc64le',
                'jfrog',
                'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.8.7/frogbot-linux-ppc64le/jfrog',
            ],
        ];
        test.each(cases)('Remote CLI Url for %s-%s', (platform, arch, fileName, expectedUrl) => {
            myOs.platform.mockImplementation(() => platform);
            myOs.arch.mockImplementation(() => arch);
            let cliUrl = utils_1.Utils.getCliUrl('2', '2.8.7', fileName, releasesRepo);
            expect(cliUrl).toBe(expectedUrl);
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
    it('Repository env tests', () => {
        process.env['GITHUB_REPOSITORY_OWNER'] = 'jfrog';
        process.env['GITHUB_REPOSITORY'] = 'jfrog/frogbot';
        utils_1.Utils.setFrogbotEnv();
        expect(process.env['JF_GIT_PROVIDER']).toBe('github');
        expect(process.env['JF_GIT_OWNER']).toBe('jfrog');
    });
});
