"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const os_1 = __importDefault(require("os"));
const utils_1 = require("../src/utils");
jest.mock('os');
describe('Frogbot Action Tests', () => {
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
            let cliUrl = utils_1.Utils.getCliUrl('1.2.3', fileName);
            expect(cliUrl).toBe(expectedUrl);
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
