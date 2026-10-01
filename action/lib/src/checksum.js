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
exports.verifyDownloadedFile = exports.artifactUrlToStorageUrl = void 0;
const crypto_1 = require("crypto");
const fs_1 = require("fs");
const core = __importStar(require("@actions/core"));
const http_client_1 = require("@actions/http-client");
function artifactUrlToStorageUrl(artifactUrl) {
    const marker = '/artifactory/';
    const index = artifactUrl.indexOf(marker);
    if (index < 0) {
        throw new Error(`Cannot derive Artifactory Storage API URL from ${artifactUrl}.`);
    }
    const prefix = artifactUrl.slice(0, index);
    let suffix = artifactUrl.slice(index + marker.length);
    const query = suffix.indexOf('?');
    if (query >= 0) {
        suffix = suffix.slice(0, query);
    }
    return `${prefix}/artifactory/api/storage/${suffix}`;
}
exports.artifactUrlToStorageUrl = artifactUrlToStorageUrl;
/**
 * Verifies a downloaded file against Artifactory checksums.
 * HEAD checksum headers are used first. A 401 or 403 response fails immediately.
 * Any other HEAD failure, or a HEAD response without MD5 and SHA1, falls back to
 * the Artifactory storage API. A [RELEASE] path is resolved to a concrete version
 * before that fallback, because the storage API does not expand [RELEASE].
 * The file is deleted when verification fails.
 */
function verifyDownloadedFile(filePath, artifactUrl, authorization) {
    return __awaiter(this, void 0, void 0, function* () {
        if (process.env.FROGBOT_INSECURE_SKIP_CHECKSUM_VERIFICATION === '1') {
            core.warning('Skipping checksum verification (FROGBOT_INSECURE_SKIP_CHECKSUM_VERIFICATION=1).');
            return;
        }
        try {
            const remote = yield loadRemoteChecksums(artifactUrl, authorization);
            const local = localChecksums(filePath);
            if (!checksumsMatch(local, remote)) {
                throw new Error(`Checksum verification failed for ${artifactUrl}. Remote md5=${remote.md5} sha1=${remote.sha1} sha256=${remote.sha256}. Local md5=${local.md5} sha1=${local.sha1} sha256=${local.sha256}.`);
            }
        }
        catch (error) {
            if ((0, fs_1.existsSync)(filePath)) {
                (0, fs_1.unlinkSync)(filePath);
            }
            throw error;
        }
    });
}
exports.verifyDownloadedFile = verifyDownloadedFile;
function loadRemoteChecksums(artifactUrl, authorization) {
    return __awaiter(this, void 0, void 0, function* () {
        const headers = authorizationHeaders(authorization);
        const client = new http_client_1.HttpClient();
        let headResponse;
        try {
            headResponse = yield client.request('HEAD', artifactUrl, null, headers);
        }
        catch (error) {
            const status = statusCodeOf(error);
            if (status === 401 || status === 403) {
                throw rejectedChecksumRequest(status);
            }
            core.debug('Checksum HEAD failed; using Artifactory Storage API.');
        }
        if (headResponse) {
            const status = headResponse.message.statusCode;
            if (status === 401 || status === 403) {
                throw rejectedChecksumRequest(status);
            }
            if (status && status >= 200 && status < 300) {
                const remote = checksumsFromHeaders(headResponse.message.headers);
                if (remote.md5 && remote.sha1) {
                    return remote;
                }
                core.debug('Checksum headers not returned by HEAD; using Artifactory Storage API.');
            }
            else {
                core.debug(`Checksum HEAD returned HTTP ${status}; using Artifactory Storage API.`);
            }
        }
        const resolvedUrl = yield resolveReleaseArtifactUrl(client, artifactUrl, headers);
        const storageUrl = artifactUrlToStorageUrl(resolvedUrl);
        const response = yield client.request('GET', storageUrl, null, headers);
        ensureStorageSuccess(response.message.statusCode, storageUrl);
        const body = yield response.readBody();
        return checksumsFromStorage(body);
    });
}
function resolveReleaseArtifactUrl(client, artifactUrl, headers) {
    return __awaiter(this, void 0, void 0, function* () {
        const token = '/[RELEASE]/';
        const index = artifactUrl.indexOf(token);
        if (index < 0) {
            return artifactUrl;
        }
        const parentUrl = artifactUrl.slice(0, index);
        const parentStorageUrl = artifactUrlToStorageUrl(parentUrl);
        core.debug(`Resolving [RELEASE] from ${parentStorageUrl}.`);
        const response = yield client.request('GET', parentStorageUrl, null, headers);
        ensureStorageSuccess(response.message.statusCode, parentStorageUrl);
        const version = latestReleaseVersion(yield response.readBody());
        if (!version) {
            throw new Error(`Could not resolve [RELEASE] from ${parentStorageUrl}.`);
        }
        return `${parentUrl}/${version}/${artifactUrl.slice(index + token.length)}`;
    });
}
function ensureStorageSuccess(status, storageUrl) {
    if (status === 401 || status === 403) {
        throw rejectedChecksumRequest(status);
    }
    if (!status || status < 200 || status >= 300) {
        throw new Error(`Artifactory Storage API returned HTTP ${status} for ${storageUrl}.`);
    }
}
function rejectedChecksumRequest(status) {
    return new Error(`Artifactory rejected the Frogbot checksum request (${status}). Check JF_ACCESS_TOKEN or JF_USER/JF_PASSWORD.`);
}
function latestReleaseVersion(body) {
    var _a;
    let parsed;
    try {
        parsed = JSON.parse(body);
    }
    catch (_b) {
        throw new Error('Artifactory storage metadata was not valid JSON.');
    }
    if (!isRecord(parsed) || !Array.isArray(parsed.children)) {
        throw new Error('Artifactory storage metadata did not include release versions.');
    }
    const versions = [];
    for (const child of parsed.children) {
        if (!isRecord(child) || typeof child.uri !== 'string') {
            continue;
        }
        const name = child.uri.replace(/^\//, '');
        if (/^\d+(?:\.\d+)+$/.test(name)) {
            versions.push(name);
        }
    }
    versions.sort(compareVersions);
    return (_a = versions[versions.length - 1]) !== null && _a !== void 0 ? _a : '';
}
function compareVersions(left, right) {
    var _a, _b;
    const leftParts = left.split('.').map((part) => Number(part));
    const rightParts = right.split('.').map((part) => Number(part));
    const length = Math.max(leftParts.length, rightParts.length);
    for (let index = 0; index < length; index++) {
        const difference = ((_a = leftParts[index]) !== null && _a !== void 0 ? _a : 0) - ((_b = rightParts[index]) !== null && _b !== void 0 ? _b : 0);
        if (difference !== 0) {
            return difference;
        }
    }
    return 0;
}
function authorizationHeaders(authorization) {
    if (!authorization) {
        return {};
    }
    return { Authorization: authorization };
}
function checksumsFromHeaders(headers) {
    return {
        md5: headerValue(headers, 'x-checksum-md5'),
        sha1: headerValue(headers, 'x-checksum-sha1'),
        sha256: headerValue(headers, 'x-checksum-sha256'),
    };
}
function headerValue(headers, name) {
    var _a;
    const raw = headers[name];
    if (Array.isArray(raw)) {
        return ((_a = raw[0]) !== null && _a !== void 0 ? _a : '').trim().toLowerCase();
    }
    return (raw !== null && raw !== void 0 ? raw : '').trim().toLowerCase();
}
function checksumsFromStorage(body) {
    let parsed;
    try {
        parsed = JSON.parse(body);
    }
    catch (_a) {
        throw new Error('Artifactory storage metadata was not valid JSON.');
    }
    if (!isRecord(parsed) || !isRecord(parsed.checksums)) {
        throw new Error('Artifactory storage metadata did not include md5/sha1 checksums.');
    }
    const md5 = stringField(parsed.checksums, 'md5');
    const sha1 = stringField(parsed.checksums, 'sha1');
    const sha256 = stringField(parsed.checksums, 'sha256');
    if (!md5 || !sha1) {
        throw new Error('Artifactory storage metadata did not include md5/sha1 checksums.');
    }
    return { md5, sha1, sha256 };
}
function isRecord(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function stringField(record, key) {
    const value = record[key];
    return typeof value === 'string' ? value.trim().toLowerCase() : '';
}
function localChecksums(filePath) {
    const bytes = (0, fs_1.readFileSync)(filePath);
    return {
        md5: (0, crypto_1.createHash)('md5').update(bytes).digest('hex'),
        sha1: (0, crypto_1.createHash)('sha1').update(bytes).digest('hex'),
        sha256: (0, crypto_1.createHash)('sha256').update(bytes).digest('hex'),
    };
}
function checksumsMatch(local, remote) {
    if (local.md5 !== remote.md5 || local.sha1 !== remote.sha1) {
        return false;
    }
    return remote.sha256 === '' || local.sha256 === remote.sha256;
}
function statusCodeOf(error) {
    if (typeof error !== 'object' || error === null || !('statusCode' in error)) {
        return undefined;
    }
    const statusCode = error.statusCode;
    return typeof statusCode === 'number' ? statusCode : undefined;
}
