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
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("crypto");
const fs_1 = require("fs");
const os_1 = require("os");
const path_1 = require("path");
const http_client_1 = require("@actions/http-client");
const checksum_1 = require("../src/checksum");
jest.mock('@actions/http-client', () => {
    const request = jest.fn();
    return {
        HttpClient: jest.fn().mockImplementation(() => ({ request })),
    };
});
const artifactUrl = 'https://releases.jfrog.io/artifactory/frogbot/v3/3.7.0/frogbot-linux-amd64/frogbot';
const storageUrl = 'https://releases.jfrog.io/artifactory/api/storage/frogbot/v3/3.7.0/frogbot-linux-amd64/frogbot';
describe('Frogbot checksum verification', () => {
    let workDir;
    let binaryPath;
    let request;
    beforeEach(() => {
        workDir = (0, fs_1.mkdtempSync)((0, path_1.join)((0, os_1.tmpdir)(), 'frogbot-checksum-'));
        binaryPath = (0, path_1.join)(workDir, 'frogbot');
        (0, fs_1.writeFileSync)(binaryPath, 'frogbot-binary');
        request = httpRequest();
        request.mockReset();
        delete process.env.FROGBOT_INSECURE_SKIP_CHECKSUM_VERIFICATION;
    });
    afterEach(() => {
        (0, fs_1.rmSync)(workDir, { recursive: true, force: true });
        delete process.env.FROGBOT_INSECURE_SKIP_CHECKSUM_VERIFICATION;
    });
    it('Derives the Artifactory storage API URL from the first artifactory segment', () => {
        expect((0, checksum_1.artifactUrlToStorageUrl)(artifactUrl)).toBe(storageUrl);
        expect((0, checksum_1.artifactUrlToStorageUrl)('https://myfrogbot.com/artifactory/frogbot-remote/artifactory/frogbot/v2/2.35.3/frogbot-linux-amd64/frogbot')).toBe('https://myfrogbot.com/artifactory/api/storage/frogbot-remote/artifactory/frogbot/v2/2.35.3/frogbot-linux-amd64/frogbot');
    });
    it('Accepts Frogbot when HEAD checksum headers match', () => __awaiter(void 0, void 0, void 0, function* () {
        request.mockResolvedValue(headResponse(checksumHeaders(binaryPath)));
        yield (0, checksum_1.verifyDownloadedFile)(binaryPath, artifactUrl, '');
        expect(request).toHaveBeenCalledTimes(1);
        expect(request).toHaveBeenCalledWith('HEAD', artifactUrl, null, {});
        expect((0, fs_1.existsSync)(binaryPath)).toBe(true);
    }));
    it('Sends the authorization header when a releases repo is configured', () => __awaiter(void 0, void 0, void 0, function* () {
        request.mockResolvedValue(headResponse(checksumHeaders(binaryPath)));
        yield (0, checksum_1.verifyDownloadedFile)(binaryPath, artifactUrl, 'Bearer token');
        expect(request).toHaveBeenCalledWith('HEAD', artifactUrl, null, { Authorization: 'Bearer token' });
    }));
    it('Rejects Frogbot and deletes it when a checksum header does not match', () => __awaiter(void 0, void 0, void 0, function* () {
        const headers = checksumHeaders(binaryPath);
        headers['x-checksum-sha256'] = 'deadbeef';
        request.mockResolvedValue(headResponse(headers));
        yield expect((0, checksum_1.verifyDownloadedFile)(binaryPath, artifactUrl, '')).rejects.toThrow('Checksum verification failed for ' + artifactUrl);
        expect((0, fs_1.existsSync)(binaryPath)).toBe(false);
    }));
    it('Accepts Frogbot when SHA256 is absent and MD5 and SHA1 match', () => __awaiter(void 0, void 0, void 0, function* () {
        const headers = checksumHeaders(binaryPath);
        delete headers['x-checksum-sha256'];
        request.mockResolvedValue(headResponse(headers));
        yield (0, checksum_1.verifyDownloadedFile)(binaryPath, artifactUrl, '');
        expect((0, fs_1.existsSync)(binaryPath)).toBe(true);
    }));
    it('Falls back to the storage API when HEAD returns no checksum headers', () => __awaiter(void 0, void 0, void 0, function* () {
        request.mockResolvedValueOnce(headResponse({})).mockResolvedValueOnce(storageResponse(binaryPath));
        yield (0, checksum_1.verifyDownloadedFile)(binaryPath, artifactUrl, '');
        expect(request).toHaveBeenNthCalledWith(2, 'GET', storageUrl, null, {});
        expect((0, fs_1.existsSync)(binaryPath)).toBe(true);
    }));
    it('Falls back to the storage API when HEAD fails for a reason other than authentication', () => __awaiter(void 0, void 0, void 0, function* () {
        request.mockRejectedValueOnce(httpError(404)).mockResolvedValueOnce(storageResponse(binaryPath));
        yield (0, checksum_1.verifyDownloadedFile)(binaryPath, artifactUrl, '');
        expect(request).toHaveBeenCalledTimes(2);
    }));
    it('Does not fall back to the storage API when Artifactory rejects the HEAD request', () => __awaiter(void 0, void 0, void 0, function* () {
        request.mockRejectedValueOnce(httpError(401));
        yield expect((0, checksum_1.verifyDownloadedFile)(binaryPath, artifactUrl, 'Bearer token')).rejects.toThrow('401');
        expect(request).toHaveBeenCalledTimes(1);
        expect((0, fs_1.existsSync)(binaryPath)).toBe(false);
    }));
    it('Does not fall back when a resolved HEAD response is unauthorized', () => __awaiter(void 0, void 0, void 0, function* () {
        request.mockResolvedValueOnce(responseWithStatus(401));
        yield expect((0, checksum_1.verifyDownloadedFile)(binaryPath, artifactUrl, 'Bearer token')).rejects.toThrow('Artifactory rejected the Frogbot checksum request (401)');
        expect(request).toHaveBeenCalledTimes(1);
        expect((0, fs_1.existsSync)(binaryPath)).toBe(false);
    }));
    it('Falls back to the storage API when a resolved HEAD response is not successful', () => __awaiter(void 0, void 0, void 0, function* () {
        request.mockResolvedValueOnce(responseWithStatus(404)).mockResolvedValueOnce(storageResponse(binaryPath));
        yield (0, checksum_1.verifyDownloadedFile)(binaryPath, artifactUrl, '');
        expect(request).toHaveBeenNthCalledWith(2, 'GET', storageUrl, null, {});
        expect((0, fs_1.existsSync)(binaryPath)).toBe(true);
    }));
    it('Reports Artifactory credentials when the storage API rejects the request', () => __awaiter(void 0, void 0, void 0, function* () {
        request.mockResolvedValueOnce(headResponse({})).mockResolvedValueOnce(responseWithStatus(403));
        yield expect((0, checksum_1.verifyDownloadedFile)(binaryPath, artifactUrl, 'Bearer token')).rejects.toThrow('Artifactory rejected the Frogbot checksum request (403)');
        expect((0, fs_1.existsSync)(binaryPath)).toBe(false);
    }));
    it('Reports the storage API status when metadata lookup is not successful', () => __awaiter(void 0, void 0, void 0, function* () {
        request.mockResolvedValueOnce(headResponse({})).mockResolvedValueOnce(responseWithStatus(500));
        yield expect((0, checksum_1.verifyDownloadedFile)(binaryPath, artifactUrl, '')).rejects.toThrow('Artifactory Storage API returned HTTP 500');
        expect((0, fs_1.existsSync)(binaryPath)).toBe(false);
    }));
    it('Resolves [RELEASE] before requesting storage metadata', () => __awaiter(void 0, void 0, void 0, function* () {
        const releaseUrl = 'https://releases.jfrog.io/artifactory/frogbot/v3/[RELEASE]/frogbot-linux-amd64/frogbot';
        const folderUrl = 'https://releases.jfrog.io/artifactory/api/storage/frogbot/v3';
        const concreteStorageUrl = 'https://releases.jfrog.io/artifactory/api/storage/frogbot/v3/3.10.0/frogbot-linux-amd64/frogbot';
        request
            .mockResolvedValueOnce(headResponse({}))
            .mockResolvedValueOnce(releaseListingResponse(['/3.6.0', '/3.10.0', '/3.7.0', '/3.9.0-SNAPSHOT']))
            .mockResolvedValueOnce(storageResponse(binaryPath));
        yield (0, checksum_1.verifyDownloadedFile)(binaryPath, releaseUrl, '');
        expect(request).toHaveBeenNthCalledWith(2, 'GET', folderUrl, null, {});
        expect(request).toHaveBeenNthCalledWith(3, 'GET', concreteStorageUrl, null, {});
        expect((0, fs_1.existsSync)(binaryPath)).toBe(true);
    }));
    it('Skips checksum verification when FROGBOT_INSECURE_SKIP_CHECKSUM_VERIFICATION is set', () => __awaiter(void 0, void 0, void 0, function* () {
        process.env.FROGBOT_INSECURE_SKIP_CHECKSUM_VERIFICATION = '1';
        yield (0, checksum_1.verifyDownloadedFile)(binaryPath, artifactUrl, '');
        expect(request).not.toHaveBeenCalled();
        expect((0, fs_1.existsSync)(binaryPath)).toBe(true);
    }));
});
function httpRequest() {
    const client = new http_client_1.HttpClient();
    return client.request;
}
function checksumHeaders(filePath) {
    return {
        'x-checksum-md5': fileHash(filePath, 'md5'),
        'x-checksum-sha1': fileHash(filePath, 'sha1'),
        'x-checksum-sha256': fileHash(filePath, 'sha256'),
    };
}
function fileHash(filePath, algorithm) {
    return (0, crypto_1.createHash)(algorithm).update((0, fs_1.readFileSync)(filePath)).digest('hex');
}
function headResponse(headers) {
    return {
        message: { statusCode: 200, headers },
        readBody: () => __awaiter(this, void 0, void 0, function* () { return ''; }),
    };
}
function responseWithStatus(statusCode) {
    return {
        message: { statusCode, headers: {} },
        readBody: () => __awaiter(this, void 0, void 0, function* () {
            throw new Error('response body should not be read');
        }),
    };
}
function releaseListingResponse(uris) {
    return {
        message: { statusCode: 200, headers: {} },
        readBody: () => __awaiter(this, void 0, void 0, function* () { return JSON.stringify({ children: uris.map((uri) => ({ uri, folder: true })) }); }),
    };
}
function storageResponse(filePath) {
    return {
        message: { statusCode: 200, headers: {} },
        readBody: () => __awaiter(this, void 0, void 0, function* () {
            return JSON.stringify({
                checksums: {
                    md5: fileHash(filePath, 'md5'),
                    sha1: fileHash(filePath, 'sha1'),
                    sha256: fileHash(filePath, 'sha256'),
                },
            });
        }),
    };
}
function httpError(statusCode) {
    const error = new Error('HTTP ' + statusCode);
    error.statusCode = statusCode;
    return error;
}
