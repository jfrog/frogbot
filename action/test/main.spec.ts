import os from 'os';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { join } from 'path';
import { exec } from '@actions/exec';
import { cacheFile, downloadTool, find } from '@actions/tool-cache';
import { verifyDownloadedFile } from '../src/checksum';
import { Utils } from '../src/utils';

jest.mock('os');
jest.mock('@actions/exec');
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

    describe('Frogbot installer URL', () => {
        afterEach(() => {
            delete process.env.JF_URL;
        });

        it('Builds a public v3 installer URL', () => {
            expect(Utils.getInstallerScriptUrl('3', '3.7.0', '')).toBe('https://releases.jfrog.io/artifactory/frogbot/v3/3.7.0/getFrogbot.sh');
        });

        it('Builds a public v2 installer URL from the version major', () => {
            expect(Utils.getInstallerScriptUrl('2', '2.35.3', '')).toBe('https://releases.jfrog.io/artifactory/frogbot/v2/2.35.3/getFrogbot.sh');
        });

        it('Builds a remote-repository installer URL', () => {
            process.env.JF_URL = 'https://myfrogbot.com/';
            expect(Utils.getInstallerScriptUrl('3', '[RELEASE]', 'frogbot-remote')).toBe(
                'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v3/[RELEASE]/getFrogbot.sh',
            );
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

    describe('getFrogbot.sh download', () => {
        let cacheDir: string;

        beforeEach(() => {
            (os.platform as jest.Mock).mockReturnValue('linux');
            const realTmp: string = jest.requireActual<typeof os>('os').tmpdir();
            (os.tmpdir as jest.Mock).mockReturnValue(realTmp);
            cacheDir = mkdtempSync(join(realTmp, 'frogbot-cache-'));
            writeFileSync(join(cacheDir, Utils.getExecutableName()), 'binary');
            (find as jest.Mock).mockReturnValue('');
            (downloadTool as jest.Mock).mockResolvedValue(join(cacheDir, 'getFrogbot.sh'));
            (verifyDownloadedFile as jest.Mock).mockResolvedValue(undefined);
            (cacheFile as jest.Mock).mockResolvedValue(cacheDir);
            (exec as jest.Mock).mockImplementation(async (_command: string, _args: string[], options: { cwd?: string }) => {
                writeFileSync(join(options.cwd ?? '', Utils.getExecutableName()), 'binary');
                return 0;
            });
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

        it('Verifies the downloaded getFrogbot.sh before running it', async () => {
            await Utils.addToPath();

            const scriptUrl: string = 'https://releases.jfrog.io/artifactory/frogbot/v3/3.7.0/getFrogbot.sh';
            expect(downloadTool).toHaveBeenCalledWith(scriptUrl, '', '');
            expect(verifyDownloadedFile).toHaveBeenCalledWith(expect.any(String), scriptUrl, '');
            expect(exec).toHaveBeenCalledWith('bash', [expect.any(String), '3.7.0'], expect.objectContaining({ cwd: expect.any(String) }));
            const verifyOrder: number = (verifyDownloadedFile as jest.Mock).mock.invocationCallOrder[0];
            const execOrder: number = (exec as jest.Mock).mock.invocationCallOrder[0];
            expect(verifyOrder).toBeLessThan(execOrder);
            expect(cacheFile).toHaveBeenCalled();
        });

        it('Does not run getFrogbot.sh when checksum verification fails', async () => {
            (verifyDownloadedFile as jest.Mock).mockRejectedValue(new Error('Checksum verification failed for getFrogbot.sh'));

            await expect(Utils.addToPath()).rejects.toThrow('Checksum verification failed for getFrogbot.sh');

            expect(exec).not.toHaveBeenCalled();
            expect(cacheFile).not.toHaveBeenCalled();
        });

        it('Downloads the v2 installer when the version input is a v2 release', async () => {
            process.env.INPUT_VERSION = '2.35.3';

            await Utils.addToPath();

            expect(downloadTool).toHaveBeenCalledWith('https://releases.jfrog.io/artifactory/frogbot/v2/2.35.3/getFrogbot.sh', '', '');
        });

        it('Downloads the v3 latest installer without using the tool cache', async () => {
            process.env.INPUT_VERSION = 'latest';

            await Utils.addToPath();

            expect(find).not.toHaveBeenCalled();
            expect(downloadTool).toHaveBeenCalledWith('https://releases.jfrog.io/artifactory/frogbot/v3/[RELEASE]/getFrogbot.sh', '', '');
            expect(exec).toHaveBeenCalledWith('bash', [expect.any(String), '[RELEASE]'], expect.objectContaining({ cwd: expect.any(String) }));
        });

        it('Passes releases-repo credentials when verifying getFrogbot.sh', async () => {
            process.env.JF_RELEASES_REPO = 'frogbot-remote';
            process.env.JF_URL = 'https://myfrogbot.com/';
            process.env.JF_ACCESS_TOKEN = 'token';

            await Utils.addToPath();

            const scriptUrl: string = 'https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v3/3.7.0/getFrogbot.sh';
            expect(downloadTool).toHaveBeenCalledWith(scriptUrl, '', 'Bearer token');
            expect(verifyDownloadedFile).toHaveBeenCalledWith(expect.any(String), scriptUrl, 'Bearer token');
        });

        it('Skips the download when the pinned version is already cached', async () => {
            (find as jest.Mock).mockReturnValue(cacheDir);

            await Utils.addToPath();

            expect(downloadTool).not.toHaveBeenCalled();
            expect(verifyDownloadedFile).not.toHaveBeenCalled();
            expect(exec).not.toHaveBeenCalled();
        });
    });
});
