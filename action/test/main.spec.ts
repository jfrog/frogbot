import os from 'os';
import { Utils } from '../src/utils';

jest.mock('os');

describe('Frogbot Action Tests', () => {
    describe('Frogbot URL Tests', () => {
        const myOs: jest.Mocked<typeof os> = os as any;
        let cases: string[][] = [
            [
                'win32' as NodeJS.Platform,
                'amd64',
                'jfrog.exe',
                'https://releases.jfrog.io/artifactory/frogbot/v1/1.2.3/frogbot-windows-amd64/jfrog.exe',
            ],
            ['darwin' as NodeJS.Platform, 'amd64', 'jfrog', 'https://releases.jfrog.io/artifactory/frogbot/v1/1.2.3/frogbot-mac-386/jfrog'],
            ['linux' as NodeJS.Platform, 'amd64', 'jfrog', 'https://releases.jfrog.io/artifactory/frogbot/v1/1.2.3/frogbot-linux-amd64/jfrog'],
            ['linux' as NodeJS.Platform, 'arm64', 'jfrog', 'https://releases.jfrog.io/artifactory/frogbot/v1/1.2.3/frogbot-linux-arm64/jfrog'],
            ['linux' as NodeJS.Platform, '386', 'jfrog', 'https://releases.jfrog.io/artifactory/frogbot/v1/1.2.3/frogbot-linux-386/jfrog'],
            ['linux' as NodeJS.Platform, 'arm', 'jfrog', 'https://releases.jfrog.io/artifactory/frogbot/v1/1.2.3/frogbot-linux-arm/jfrog'],
            ['linux' as NodeJS.Platform, 'ppc64', 'jfrog', 'https://releases.jfrog.io/artifactory/frogbot/v1/1.2.3/frogbot-linux-ppc64/jfrog'],
            ['linux' as NodeJS.Platform, 'ppc64le', 'jfrog', 'https://releases.jfrog.io/artifactory/frogbot/v1/1.2.3/frogbot-linux-ppc64le/jfrog'],
        ];

        test.each(cases)('CLI Url for %s-%s', (platform, arch, fileName, expectedUrl) => {
            myOs.platform.mockImplementation(() => <NodeJS.Platform>platform);
            myOs.arch.mockImplementation(() => arch);
            let cliUrl: string = Utils.getCliUrl('1.2.3', fileName);
            expect(cliUrl).toBe(expectedUrl);
        });
    });

    it('Repository env tests', () => {
        process.env['GITHUB_REPOSITORY_OWNER'] = 'jfrog';
        process.env['GITHUB_REPOSITORY'] = 'jfrog/frogbot';
        Utils.setFrogbotEnv();
        expect(process.env['JF_GIT_PROVIDER']).toBe('github');
        expect(process.env['JF_GIT_OWNER']).toBe('jfrog');
    });
});
