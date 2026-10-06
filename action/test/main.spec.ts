import os from 'os';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { join } from 'path';
import { cacheFile, downloadTool, find } from '@actions/tool-cache';
import { verifyDownloadedFile } from '../src/checksum';
import { Utils } from '../src/utils';

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
        const repositoryRoot: string = join(__dirname, '..', '..');

        it('Declares the Auto-PR inputs in the root action manifest', () => {
            const manifest: string = readFileSync(join(repositoryRoot, 'action.yml'), 'utf8');

            expect(manifest).toContain('command:');
            expect(manifest).toContain('component-name:');
            expect(manifest).toContain('affected-version:');
            expect(manifest).toContain('fix-version:');
            expect(manifest).toContain('branch-name:');
            expect(manifest).toContain('commit-hash:');
            expect(manifest).toContain('main: "action/lib/main.js"');
        });

        it('Passes the repository default branch when branch-name is omitted', () => {
            const workflow: string = readFileSync(join(repositoryRoot, '.github', 'workflows', 'frogbot-auto-pr.yml'), 'utf8');

            expect(workflow).toContain('branch-name: ${{ inputs.branch-name || github.event.repository.default_branch }}');
        });

        it('Invokes the local Auto-PR action in CI', () => {
            const workflow: string = readFileSync(join(repositoryRoot, '.github', 'workflows', 'action-test.yml'), 'utf8');

            expect(workflow).toContain('uses: ./');
        });
    });

    describe('Frogbot URL Tests', () => {
        const myOs: jest.Mocked<typeof os> = os as jest.Mocked<typeof os>;
        const cases: string[][] = [
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

        test.each(cases)('CLI Url for %s-%s', (platform: string, arch: string, fileName: string, expectedUrl: string) => {
            myOs.platform.mockImplementation(() => platform as NodeJS.Platform);
            myOs.arch.mockImplementation(() => arch);
            expect(Utils.getCliUrl('1', '1.2.3', fileName, '')).toBe(expectedUrl);
        });
    });

    describe('Frogbot URL Tests With Remote Artifactory', () => {
        const myOs: jest.Mocked<typeof os> = os as jest.Mocked<typeof os>;
        const releasesRepo: string = 'frogbot-remote';
        const cases: string[][] = [
            [
                'win32',
                'amd64',
                'jfrog.exe',
                'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.8.7/frogbot-windows-amd64/jfrog.exe',
            ],
            ['darwin', 'amd64', 'jfrog', 'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.8.7/frogbot-mac-386/jfrog'],
            ['darwin', 'arm64', 'jfrog', 'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.8.7/frogbot-mac-arm64/jfrog'],
            ['linux', 'amd64', 'jfrog', 'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.8.7/frogbot-linux-amd64/jfrog'],
            ['linux', 'arm64', 'jfrog', 'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.8.7/frogbot-linux-arm64/jfrog'],
            ['linux', '386', 'jfrog', 'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.8.7/frogbot-linux-386/jfrog'],
            ['linux', 'arm', 'jfrog', 'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.8.7/frogbot-linux-arm/jfrog'],
            ['linux', 'ppc64', 'jfrog', 'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.8.7/frogbot-linux-ppc64/jfrog'],
            [
                'linux',
                'ppc64le',
                'jfrog',
                'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.8.7/frogbot-linux-ppc64le/jfrog',
            ],
        ];

        beforeEach(() => {
            process.env.JF_URL = 'https://myfrogbot.com/';
        });

        afterEach(() => {
            delete process.env.JF_URL;
        });

        test.each(cases)('Remote CLI Url for %s-%s', (platform: string, arch: string, fileName: string, expectedUrl: string) => {
            myOs.platform.mockImplementation(() => platform as NodeJS.Platform);
            myOs.arch.mockImplementation(() => arch);
            expect(Utils.getCliUrl('2', '2.8.7', fileName, releasesRepo)).toBe(expectedUrl);
        });
    });

    describe('Generate auth string', () => {
        it('Should return an empty string if releasesRepo is falsy', () => {
            const result: string = Utils.generateAuthString('');
            expect(result).toBe('');
        });

        it('Should generate a Bearer token if accessToken is provided', () => {
            process.env.JF_ACCESS_TOKEN = 'yourAccessToken';
            const result: string = Utils.generateAuthString('yourReleasesRepo');
            expect(result).toBe('Bearer yourAccessToken');
        });

        it('Should generate a Basic token if username and password are provided', () => {
            process.env.JF_USER = 'yourUsername';
            process.env.JF_PASSWORD = 'yourPassword';
            const result: string = Utils.generateAuthString('yourReleasesRepo');
            expect(result).toBe('Basic eW91clVzZXJuYW1lOnlvdXJQYXNzd29yZA==');
        });

        it('Should return an empty string if no credentials are provided', () => {
            const result: string = Utils.generateAuthString('yourReleasesRepo');
            expect(result).toBe('');
        });
    });

    it('Repository env tests', async () => {
        process.env['GITHUB_REPOSITORY_OWNER'] = 'jfrog';
        process.env['GITHUB_REPOSITORY'] = 'jfrog/frogbot';
        process.env['GITHUB_TOKEN'] = 'ghp_test_token';
        await Utils.setFrogbotEnv();
        expect(process.env['JF_GIT_PROVIDER']).toBe('github');
        expect(process.env['JF_GIT_OWNER']).toBe('jfrog');
    });

    describe('Auto-detect Git token', () => {
        afterEach(() => {
            delete process.env.JF_GIT_TOKEN;
            delete process.env.GITHUB_TOKEN;
            delete process.env.GITHUB_REPOSITORY_OWNER;
            delete process.env.GITHUB_REPOSITORY;
        });

        it('Should auto-detect JF_GIT_TOKEN from GITHUB_TOKEN', async () => {
            process.env['GITHUB_TOKEN'] = 'ghp_test_token_123';
            process.env['GITHUB_REPOSITORY_OWNER'] = 'jfrog';
            process.env['GITHUB_REPOSITORY'] = 'jfrog/frogbot';

            await Utils.setFrogbotEnv();

            expect(process.env['JF_GIT_TOKEN']).toBe('ghp_test_token_123');
        });

        it('Should use existing JF_GIT_TOKEN if already set', async () => {
            process.env['JF_GIT_TOKEN'] = 'custom_token_456';
            process.env['GITHUB_TOKEN'] = 'ghp_test_token_123';
            process.env['GITHUB_REPOSITORY_OWNER'] = 'jfrog';
            process.env['GITHUB_REPOSITORY'] = 'jfrog/frogbot';

            await Utils.setFrogbotEnv();

            expect(process.env['JF_GIT_TOKEN']).toBe('custom_token_456');
        });

        it('Should throw error if no token is available', async () => {
            process.env['GITHUB_REPOSITORY_OWNER'] = 'jfrog';
            process.env['GITHUB_REPOSITORY'] = 'jfrog/frogbot';

            await expect(Utils.setFrogbotEnv()).rejects.toThrow('Git token not found');
        });
    });

    describe('Auto-detect API endpoint', () => {
        afterEach(() => {
            delete process.env.JF_GIT_API_ENDPOINT;
            delete process.env.GITHUB_API_URL;
            delete process.env.GITHUB_TOKEN;
            delete process.env.GITHUB_REPOSITORY_OWNER;
            delete process.env.GITHUB_REPOSITORY;
        });

        it('Should auto-detect JF_GIT_API_ENDPOINT from GITHUB_API_URL', async () => {
            process.env['GITHUB_API_URL'] = 'https://api.github.enterprise.com';
            process.env['GITHUB_TOKEN'] = 'ghp_test_token';
            process.env['GITHUB_REPOSITORY_OWNER'] = 'jfrog';
            process.env['GITHUB_REPOSITORY'] = 'jfrog/frogbot';

            await Utils.setFrogbotEnv();

            expect(process.env['JF_GIT_API_ENDPOINT']).toBe('https://api.github.enterprise.com');
        });

        it('Should use default API endpoint if GITHUB_API_URL not set', async () => {
            process.env['GITHUB_TOKEN'] = 'ghp_test_token';
            process.env['GITHUB_REPOSITORY_OWNER'] = 'jfrog';
            process.env['GITHUB_REPOSITORY'] = 'jfrog/frogbot';

            await Utils.setFrogbotEnv();

            expect(process.env['JF_GIT_API_ENDPOINT']).toBe('https://api.github.com');
        });

        it('Should use existing JF_GIT_API_ENDPOINT if already set', async () => {
            process.env['JF_GIT_API_ENDPOINT'] = 'https://custom.api.com';
            process.env['GITHUB_API_URL'] = 'https://api.github.enterprise.com';
            process.env['GITHUB_TOKEN'] = 'ghp_test_token';
            process.env['GITHUB_REPOSITORY_OWNER'] = 'jfrog';
            process.env['GITHUB_REPOSITORY'] = 'jfrog/frogbot';

            await Utils.setFrogbotEnv();

            expect(process.env['JF_GIT_API_ENDPOINT']).toBe('https://custom.api.com');
        });
    });

    describe('Auto-detect server URL', () => {
        afterEach(() => {
            delete process.env.JF_GIT_SERVER_URL;
            delete process.env.GITHUB_SERVER_URL;
            delete process.env.GITHUB_TOKEN;
            delete process.env.GITHUB_REPOSITORY_OWNER;
            delete process.env.GITHUB_REPOSITORY;
        });

        it('Should auto-detect JF_GIT_SERVER_URL from GITHUB_SERVER_URL', async () => {
            process.env['GITHUB_SERVER_URL'] = 'https://myenterprise.github.com';
            process.env['GITHUB_TOKEN'] = 'ghp_test_token';
            process.env['GITHUB_REPOSITORY_OWNER'] = 'jfrog';
            process.env['GITHUB_REPOSITORY'] = 'jfrog/frogbot';
            await Utils.setFrogbotEnv();
            expect(process.env['JF_GIT_SERVER_URL']).toBe('https://myenterprise.github.com');
        });

        it('Should default JF_GIT_SERVER_URL to https://github.com if GITHUB_SERVER_URL not set', async () => {
            process.env['GITHUB_TOKEN'] = 'ghp_test_token';
            process.env['GITHUB_REPOSITORY_OWNER'] = 'jfrog';
            process.env['GITHUB_REPOSITORY'] = 'jfrog/frogbot';
            await Utils.setFrogbotEnv();
            expect(process.env['JF_GIT_SERVER_URL']).toBe('https://github.com');
        });

        it('Should use existing JF_GIT_SERVER_URL if already set', async () => {
            process.env['JF_GIT_SERVER_URL'] = 'https://custom.server.com';
            process.env['GITHUB_SERVER_URL'] = 'https://myenterprise.github.com';
            process.env['GITHUB_TOKEN'] = 'ghp_test_token';
            process.env['GITHUB_REPOSITORY_OWNER'] = 'jfrog';
            process.env['GITHUB_REPOSITORY'] = 'jfrog/frogbot';
            await Utils.setFrogbotEnv();
            expect(process.env['JF_GIT_SERVER_URL']).toBe('https://custom.server.com');
        });
    });

    describe('Frogbot download', () => {
        let cacheDir: string;
        let binaryPath: string;

        beforeEach(() => {
            (os.platform as jest.Mock).mockReturnValue('linux');
            (os.arch as jest.Mock).mockReturnValue('x64');
            const realTmp: string = jest.requireActual<typeof os>('os').tmpdir();
            cacheDir = mkdtempSync(join(realTmp, 'frogbot-cache-'));
            binaryPath = join(cacheDir, 'frogbot');
            writeFileSync(binaryPath, 'binary');
            (find as jest.Mock).mockReturnValue('');
            (downloadTool as jest.Mock).mockResolvedValue(binaryPath);
            (verifyDownloadedFile as jest.Mock).mockResolvedValue(undefined);
            (cacheFile as jest.Mock).mockResolvedValue(cacheDir);
            process.env.INPUT_VERSION = '3.7.0';
        });

        afterEach(() => {
            rmSync(cacheDir, { recursive: true, force: true });
            delete process.env.INPUT_VERSION;
            delete process.env.JF_RELEASES_REPO;
            delete process.env.JF_URL;
            delete process.env.JF_ACCESS_TOKEN;
            jest.clearAllMocks();
        });

        it('Verifies the downloaded Frogbot binary before caching it', async () => {
            await Utils.addToPath();

            const cliUrl: string = 'https://releases.jfrog.io/artifactory/frogbot/v3/3.7.0/frogbot-linux-amd64/frogbot';
            expect(downloadTool).toHaveBeenCalledWith(cliUrl, '', '');
            expect(verifyDownloadedFile).toHaveBeenCalledWith(binaryPath, cliUrl, '');
            expect(cacheFile).toHaveBeenCalledWith(binaryPath, 'frogbot', 'frogbot', '3.7.0');
            const verifyOrder: number = (verifyDownloadedFile as jest.Mock).mock.invocationCallOrder[0];
            const cacheOrder: number = (cacheFile as jest.Mock).mock.invocationCallOrder[0];
            expect(verifyOrder).toBeLessThan(cacheOrder);
        });

        it('Does not cache Frogbot when checksum verification fails', async () => {
            (verifyDownloadedFile as jest.Mock).mockRejectedValue(new Error('Checksum verification failed'));

            await expect(Utils.addToPath()).rejects.toThrow('Checksum verification failed');

            expect(cacheFile).not.toHaveBeenCalled();
        });

        it('Downloads the v2 binary when the version input is a v2 release', async () => {
            process.env.INPUT_VERSION = '2.35.3';

            await Utils.addToPath();

            expect(downloadTool).toHaveBeenCalledWith('https://releases.jfrog.io/artifactory/frogbot/v2/2.35.3/frogbot-linux-amd64/frogbot', '', '');
        });

        it('Downloads the v3 latest binary without using the tool cache', async () => {
            process.env.INPUT_VERSION = 'latest';

            await Utils.addToPath();

            expect(find).not.toHaveBeenCalled();
            expect(downloadTool).toHaveBeenCalledWith(
                'https://releases.jfrog.io/artifactory/frogbot/v3/[RELEASE]/frogbot-linux-amd64/frogbot',
                '',
                '',
            );
        });

        it('Passes releases-repo credentials when verifying Frogbot', async () => {
            process.env.JF_RELEASES_REPO = 'frogbot-remote';
            process.env.JF_URL = 'https://myfrogbot.com/';
            process.env.JF_ACCESS_TOKEN = 'token';

            await Utils.addToPath();

            const cliUrl: string = 'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v3/3.7.0/frogbot-linux-amd64/frogbot';
            expect(downloadTool).toHaveBeenCalledWith(cliUrl, '', 'Bearer token');
            expect(verifyDownloadedFile).toHaveBeenCalledWith(binaryPath, cliUrl, 'Bearer token');
        });

        it('Skips the download when the pinned version is already cached', async () => {
            (find as jest.Mock).mockReturnValue(cacheDir);

            await Utils.addToPath();

            expect(find).toHaveBeenCalledWith('frogbot', '3.7.0');
            expect(downloadTool).not.toHaveBeenCalled();
            expect(verifyDownloadedFile).not.toHaveBeenCalled();
            expect(cacheFile).not.toHaveBeenCalled();
        });
    });
});
