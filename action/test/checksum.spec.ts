import { createHash } from 'crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { HttpClient } from '@actions/http-client';
import { artifactUrlToStorageUrl, verifyDownloadedFile } from '../src/checksum';

jest.mock('@actions/http-client', () => {
    const request: jest.Mock = jest.fn();
    return {
        HttpClient: jest.fn().mockImplementation(() => ({ request })),
    };
});

const artifactUrl: string = 'https://releases.jfrog.io/artifactory/frogbot/v3/3.7.0/getFrogbot.sh';
const storageUrl: string = 'https://releases.jfrog.io/artifactory/api/storage/frogbot/v3/3.7.0/getFrogbot.sh';

describe('getFrogbot.sh checksum verification', () => {
    let workDir: string;
    let scriptPath: string;
    let request: jest.Mock;

    beforeEach(() => {
        workDir = mkdtempSync(join(tmpdir(), 'frogbot-checksum-'));
        scriptPath = join(workDir, 'getFrogbot.sh');
        writeFileSync(scriptPath, '#!/bin/bash\necho frogbot\n');
        request = httpRequest();
        request.mockReset();
        delete process.env.FROGBOT_INSECURE_SKIP_CHECKSUM_VERIFICATION;
    });

    afterEach(() => {
        rmSync(workDir, { recursive: true, force: true });
        delete process.env.FROGBOT_INSECURE_SKIP_CHECKSUM_VERIFICATION;
    });

    it('Derives the Artifactory storage API URL from the first artifactory segment', () => {
        expect(artifactUrlToStorageUrl(artifactUrl)).toBe(storageUrl);
        expect(artifactUrlToStorageUrl('https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.35.3/getFrogbot.sh')).toBe(
            'https://myfrogbot.com/artifactory/api/storage/frogbot-remote/artifactory/frogbot/v2/2.35.3/getFrogbot.sh',
        );
    });

    it('Accepts getFrogbot.sh when HEAD checksum headers match', async () => {
        request.mockResolvedValue(headResponse(checksumHeaders(scriptPath)));

        await verifyDownloadedFile(scriptPath, artifactUrl, '');

        expect(request).toHaveBeenCalledTimes(1);
        expect(request).toHaveBeenCalledWith('HEAD', artifactUrl, null, {});
        expect(existsSync(scriptPath)).toBe(true);
    });

    it('Sends the installer authorization header when a releases repo is configured', async () => {
        request.mockResolvedValue(headResponse(checksumHeaders(scriptPath)));

        await verifyDownloadedFile(scriptPath, artifactUrl, 'Bearer token');

        expect(request).toHaveBeenCalledWith('HEAD', artifactUrl, null, { Authorization: 'Bearer token' });
    });

    it('Rejects getFrogbot.sh and deletes it when a checksum header does not match', async () => {
        const headers: Record<string, string> = checksumHeaders(scriptPath);
        headers['x-checksum-sha256'] = 'deadbeef';
        request.mockResolvedValue(headResponse(headers));

        await expect(verifyDownloadedFile(scriptPath, artifactUrl, '')).rejects.toThrow('Checksum verification failed for getFrogbot.sh');
        expect(existsSync(scriptPath)).toBe(false);
    });

    it('Accepts getFrogbot.sh when SHA256 is absent and MD5 and SHA1 match', async () => {
        const headers: Record<string, string> = checksumHeaders(scriptPath);
        delete headers['x-checksum-sha256'];
        request.mockResolvedValue(headResponse(headers));

        await verifyDownloadedFile(scriptPath, artifactUrl, '');

        expect(existsSync(scriptPath)).toBe(true);
    });

    it('Falls back to the storage API when HEAD returns no checksum headers', async () => {
        request.mockResolvedValueOnce(headResponse({})).mockResolvedValueOnce(storageResponse(scriptPath));

        await verifyDownloadedFile(scriptPath, artifactUrl, '');

        expect(request).toHaveBeenNthCalledWith(2, 'GET', storageUrl, null, {});
        expect(existsSync(scriptPath)).toBe(true);
    });

    it('Falls back to the storage API when HEAD fails for a reason other than authentication', async () => {
        request.mockRejectedValueOnce(httpError(404)).mockResolvedValueOnce(storageResponse(scriptPath));

        await verifyDownloadedFile(scriptPath, artifactUrl, '');

        expect(request).toHaveBeenCalledTimes(2);
    });

    it('Does not fall back to the storage API when Artifactory rejects the HEAD request', async () => {
        request.mockRejectedValueOnce(httpError(401));

        await expect(verifyDownloadedFile(scriptPath, artifactUrl, 'Bearer token')).rejects.toThrow('401');
        expect(request).toHaveBeenCalledTimes(1);
        expect(existsSync(scriptPath)).toBe(false);
    });

    it('Skips checksum verification when FROGBOT_INSECURE_SKIP_CHECKSUM_VERIFICATION is set', async () => {
        process.env.FROGBOT_INSECURE_SKIP_CHECKSUM_VERIFICATION = '1';

        await verifyDownloadedFile(scriptPath, artifactUrl, '');

        expect(request).not.toHaveBeenCalled();
        expect(existsSync(scriptPath)).toBe(true);
    });
});

function httpRequest(): jest.Mock {
    const client: HttpClient = new HttpClient();
    return client.request as jest.Mock;
}

function checksumHeaders(filePath: string): Record<string, string> {
    return {
        'x-checksum-md5': fileHash(filePath, 'md5'),
        'x-checksum-sha1': fileHash(filePath, 'sha1'),
        'x-checksum-sha256': fileHash(filePath, 'sha256'),
    };
}

function fileHash(filePath: string, algorithm: string): string {
    return createHash(algorithm).update(readFileSync(filePath)).digest('hex');
}

function headResponse(headers: Record<string, string>): {
    message: { statusCode: number; headers: Record<string, string> };
    readBody: () => Promise<string>;
} {
    return {
        message: { statusCode: 200, headers },
        readBody: async (): Promise<string> => '',
    };
}

function storageResponse(filePath: string): { message: { statusCode: number; headers: Record<string, string> }; readBody: () => Promise<string> } {
    return {
        message: { statusCode: 200, headers: {} },
        readBody: async (): Promise<string> =>
            JSON.stringify({
                checksums: {
                    md5: fileHash(filePath, 'md5'),
                    sha1: fileHash(filePath, 'sha1'),
                    sha256: fileHash(filePath, 'sha256'),
                },
            }),
    };
}

function httpError(statusCode: number): Error {
    const error: Error & { statusCode?: number } = new Error('HTTP ' + statusCode);
    error.statusCode = statusCode;
    return error;
}
