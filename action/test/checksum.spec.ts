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

const artifactUrl: string = 'https://releases.jfrog.io/artifactory/frogbot/v3/3.7.0/frogbot-linux-amd64/frogbot';
const storageUrl: string = 'https://releases.jfrog.io/artifactory/api/storage/frogbot/v3/3.7.0/frogbot-linux-amd64/frogbot';

describe('Frogbot checksum verification', () => {
    let workDir: string;
    let binaryPath: string;
    let request: jest.Mock;

    beforeEach(() => {
        workDir = mkdtempSync(join(tmpdir(), 'frogbot-checksum-'));
        binaryPath = join(workDir, 'frogbot');
        writeFileSync(binaryPath, 'frogbot-binary');
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
        expect(
            artifactUrlToStorageUrl('https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.35.3/frogbot-linux-amd64/frogbot'),
        ).toBe('https://myfrogbot.com/artifactory/api/storage/frogbot-remote/artifactory/frogbot/v2/2.35.3/frogbot-linux-amd64/frogbot');
    });

    it('Accepts Frogbot when HEAD checksum headers match', async () => {
        request.mockResolvedValue(headResponse(checksumHeaders(binaryPath)));

        await verifyDownloadedFile(binaryPath, artifactUrl, '');

        expect(request).toHaveBeenCalledTimes(1);
        expect(request).toHaveBeenCalledWith('HEAD', artifactUrl, null, {});
        expect(existsSync(binaryPath)).toBe(true);
    });

    it('Sends the authorization header when a releases repo is configured', async () => {
        request.mockResolvedValue(headResponse(checksumHeaders(binaryPath)));

        await verifyDownloadedFile(binaryPath, artifactUrl, 'Bearer token');

        expect(request).toHaveBeenCalledWith('HEAD', artifactUrl, null, { Authorization: 'Bearer token' });
    });

    it('Rejects Frogbot and deletes it when a checksum header does not match', async () => {
        const headers: Record<string, string> = checksumHeaders(binaryPath);
        headers['x-checksum-sha256'] = 'deadbeef';
        request.mockResolvedValue(headResponse(headers));

        await expect(verifyDownloadedFile(binaryPath, artifactUrl, '')).rejects.toThrow('Checksum verification failed for ' + artifactUrl);
        expect(existsSync(binaryPath)).toBe(false);
    });

    it('Accepts Frogbot when SHA256 is absent and MD5 and SHA1 match', async () => {
        const headers: Record<string, string> = checksumHeaders(binaryPath);
        delete headers['x-checksum-sha256'];
        request.mockResolvedValue(headResponse(headers));

        await verifyDownloadedFile(binaryPath, artifactUrl, '');

        expect(existsSync(binaryPath)).toBe(true);
    });

    it('Falls back to the storage API when HEAD returns no checksum headers', async () => {
        request.mockResolvedValueOnce(headResponse({})).mockResolvedValueOnce(storageResponse(binaryPath));

        await verifyDownloadedFile(binaryPath, artifactUrl, '');

        expect(request).toHaveBeenNthCalledWith(2, 'GET', storageUrl, null, {});
        expect(existsSync(binaryPath)).toBe(true);
    });

    it('Falls back to the storage API when HEAD fails for a reason other than authentication', async () => {
        request.mockRejectedValueOnce(httpError(404)).mockResolvedValueOnce(storageResponse(binaryPath));

        await verifyDownloadedFile(binaryPath, artifactUrl, '');

        expect(request).toHaveBeenCalledTimes(2);
    });

    it('Does not fall back to the storage API when Artifactory rejects the HEAD request', async () => {
        request.mockRejectedValueOnce(httpError(401));

        await expect(verifyDownloadedFile(binaryPath, artifactUrl, 'Bearer token')).rejects.toThrow('401');
        expect(request).toHaveBeenCalledTimes(1);
        expect(existsSync(binaryPath)).toBe(false);
    });

    it('Does not fall back when a resolved HEAD response is unauthorized', async () => {
        request.mockResolvedValueOnce(responseWithStatus(401));

        await expect(verifyDownloadedFile(binaryPath, artifactUrl, 'Bearer token')).rejects.toThrow(
            'Artifactory rejected the Frogbot checksum request (401)',
        );
        expect(request).toHaveBeenCalledTimes(1);
        expect(existsSync(binaryPath)).toBe(false);
    });

    it('Falls back to the storage API when a resolved HEAD response is not successful', async () => {
        request.mockResolvedValueOnce(responseWithStatus(404)).mockResolvedValueOnce(storageResponse(binaryPath));

        await verifyDownloadedFile(binaryPath, artifactUrl, '');

        expect(request).toHaveBeenNthCalledWith(2, 'GET', storageUrl, null, {});
        expect(existsSync(binaryPath)).toBe(true);
    });

    it('Reports Artifactory credentials when the storage API rejects the request', async () => {
        request.mockResolvedValueOnce(headResponse({})).mockResolvedValueOnce(responseWithStatus(403));

        await expect(verifyDownloadedFile(binaryPath, artifactUrl, 'Bearer token')).rejects.toThrow(
            'Artifactory rejected the Frogbot checksum request (403)',
        );
        expect(existsSync(binaryPath)).toBe(false);
    });

    it('Reports the storage API status when metadata lookup is not successful', async () => {
        request.mockResolvedValueOnce(headResponse({})).mockResolvedValueOnce(responseWithStatus(500));

        await expect(verifyDownloadedFile(binaryPath, artifactUrl, '')).rejects.toThrow('Artifactory Storage API returned HTTP 500');
        expect(existsSync(binaryPath)).toBe(false);
    });

    it('Fails a [RELEASE] download when HEAD returns no checksum headers', async () => {
        const releaseUrl: string = 'https://releases.jfrog.io/artifactory/frogbot/v3/[RELEASE]/frogbot-linux-amd64/frogbot';
        request.mockResolvedValueOnce(headResponse({}));

        await expect(verifyDownloadedFile(binaryPath, releaseUrl, '')).rejects.toThrow(
            'Artifactory did not return checksum headers for ' + releaseUrl,
        );
        expect(request).toHaveBeenCalledTimes(1);
        expect(existsSync(binaryPath)).toBe(false);
    });

    it('Skips checksum verification when FROGBOT_INSECURE_SKIP_CHECKSUM_VERIFICATION is set', async () => {
        process.env.FROGBOT_INSECURE_SKIP_CHECKSUM_VERIFICATION = '1';

        await verifyDownloadedFile(binaryPath, artifactUrl, '');

        expect(request).not.toHaveBeenCalled();
        expect(existsSync(binaryPath)).toBe(true);
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

function responseWithStatus(statusCode: number): {
    message: { statusCode: number; headers: Record<string, string> };
    readBody: () => Promise<string>;
} {
    return {
        message: { statusCode, headers: {} },
        readBody: async (): Promise<string> => {
            throw new Error('response body should not be read');
        },
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
