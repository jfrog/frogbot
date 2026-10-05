import { createHash } from 'crypto';
import { existsSync, readFileSync, unlinkSync } from 'fs';
import { IncomingHttpHeaders, OutgoingHttpHeaders } from 'http';
import * as core from '@actions/core';
import { HttpClient, HttpClientResponse } from '@actions/http-client';

export interface RemoteChecksums {
    md5: string;
    sha1: string;
    sha256: string;
}

export function artifactUrlToStorageUrl(artifactUrl: string): string {
    const marker: string = '/artifactory/';
    const index: number = artifactUrl.indexOf(marker);
    if (index < 0) {
        throw new Error(`Cannot derive Artifactory Storage API URL from ${artifactUrl}.`);
    }
    const prefix: string = artifactUrl.slice(0, index);
    let suffix: string = artifactUrl.slice(index + marker.length);
    const query: number = suffix.indexOf('?');
    if (query >= 0) {
        suffix = suffix.slice(0, query);
    }
    return `${prefix}/artifactory/api/storage/${suffix}`;
}

export async function verifyDownloadedFile(filePath: string, artifactUrl: string, authorization: string): Promise<void> {
    if (process.env.FROGBOT_INSECURE_SKIP_CHECKSUM_VERIFICATION === '1') {
        core.warning('Skipping checksum verification (FROGBOT_INSECURE_SKIP_CHECKSUM_VERIFICATION=1).');
        return;
    }

    try {
        const remote: RemoteChecksums = await loadRemoteChecksums(artifactUrl, authorization);
        const local: RemoteChecksums = localChecksums(filePath);
        if (!checksumsMatch(local, remote)) {
            throw new Error(
                `Checksum verification failed for ${artifactUrl}. Remote md5=${remote.md5} sha1=${remote.sha1} sha256=${remote.sha256}. Local md5=${local.md5} sha1=${local.sha1} sha256=${local.sha256}.`,
            );
        }
    } catch (error) {
        deleteRejectedDownload(filePath);
        throw error;
    }
}

async function loadRemoteChecksums(artifactUrl: string, authorization: string): Promise<RemoteChecksums> {
    const headers: OutgoingHttpHeaders = authorizationHeaders(authorization);
    // Redirects stay off so checksum headers and status come from Artifactory.
    // A GET of the same URL returns 302 to object storage, which has no X-Checksum-* headers,
    // and a 401 or 403 from that target would be reported as bad JFrog credentials.
    const client: HttpClient = new HttpClient(undefined, undefined, { allowRedirects: false });
    let headResponse: HttpClientResponse | undefined;
    try {
        headResponse = await client.request('HEAD', artifactUrl, null, headers);
    } catch (error) {
        const status: number | undefined = statusCodeOf(error);
        if (status === 401 || status === 403) {
            throw rejectedChecksumRequest(status);
        }
        core.debug('Checksum HEAD failed; using Artifactory Storage API.');
    }

    if (headResponse) {
        const status: number | undefined = headResponse.message.statusCode;
        if (status === 401 || status === 403) {
            throw rejectedChecksumRequest(status);
        }
        if (status && status >= 200 && status < 300) {
            const remote: RemoteChecksums = checksumsFromHeaders(headResponse.message.headers);
            if (remote.md5 && remote.sha1) {
                return remote;
            }
            core.debug('Checksum headers not returned by HEAD; using Artifactory Storage API.');
        } else {
            core.debug(`Checksum HEAD returned HTTP ${status}; using Artifactory Storage API.`);
        }
    }

    if (artifactUrl.includes('/[RELEASE]/')) {
        throw new Error(`Artifactory did not return checksum headers for ${artifactUrl}. Cannot verify a [RELEASE] download without those headers.`);
    }

    const storageUrl: string = artifactUrlToStorageUrl(artifactUrl);
    const response: HttpClientResponse = await client.request('GET', storageUrl, null, headers);
    ensureStorageSuccess(response.message.statusCode, storageUrl);
    const body: string = await response.readBody();
    return checksumsFromStorage(body);
}

function ensureStorageSuccess(status: number | undefined, storageUrl: string): void {
    if (status === 401 || status === 403) {
        throw rejectedChecksumRequest(status);
    }
    if (!status || status < 200 || status >= 300) {
        throw new Error(`Artifactory Storage API returned HTTP ${status} for ${storageUrl}.`);
    }
}

function rejectedChecksumRequest(status: number): Error {
    return new Error(`Artifactory rejected the Frogbot checksum request (${status}). Check JF_ACCESS_TOKEN or JF_USER/JF_PASSWORD.`);
}

function authorizationHeaders(authorization: string): OutgoingHttpHeaders {
    if (!authorization) {
        return {};
    }
    return { Authorization: authorization };
}

function checksumsFromHeaders(headers: IncomingHttpHeaders): RemoteChecksums {
    return {
        md5: headerValue(headers, 'x-checksum-md5'),
        sha1: headerValue(headers, 'x-checksum-sha1'),
        sha256: headerValue(headers, 'x-checksum-sha256'),
    };
}

function headerValue(headers: IncomingHttpHeaders, name: string): string {
    const raw: string | string[] | undefined = headers[name];
    if (Array.isArray(raw)) {
        return (raw[0] ?? '').trim().toLowerCase();
    }
    return (raw ?? '').trim().toLowerCase();
}

function checksumsFromStorage(body: string): RemoteChecksums {
    let parsed: unknown;
    try {
        parsed = JSON.parse(body);
    } catch {
        throw new Error('Artifactory storage metadata was not valid JSON.');
    }
    if (!isRecord(parsed) || !isRecord(parsed.checksums)) {
        throw new Error('Artifactory storage metadata did not include md5/sha1 checksums.');
    }
    const md5: string = stringField(parsed.checksums, 'md5');
    const sha1: string = stringField(parsed.checksums, 'sha1');
    const sha256: string = stringField(parsed.checksums, 'sha256');
    if (!md5 || !sha1) {
        throw new Error('Artifactory storage metadata did not include md5/sha1 checksums.');
    }
    return { md5, sha1, sha256 };
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stringField(record: Record<string, unknown>, key: string): string {
    const value: unknown = record[key];
    return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

function deleteRejectedDownload(filePath: string): void {
    try {
        if (existsSync(filePath)) {
            unlinkSync(filePath);
        }
    } catch (deleteError) {
        const message: string = deleteError instanceof Error ? deleteError.message : String(deleteError);
        core.warning(`Failed to delete ${filePath} after checksum verification failed: ${message}`);
    }
}

function localChecksums(filePath: string): RemoteChecksums {
    const bytes: Buffer = readFileSync(filePath);
    return {
        md5: createHash('md5').update(bytes).digest('hex'),
        sha1: createHash('sha1').update(bytes).digest('hex'),
        sha256: createHash('sha256').update(bytes).digest('hex'),
    };
}

function checksumsMatch(local: RemoteChecksums, remote: RemoteChecksums): boolean {
    if (local.md5 !== remote.md5 || local.sha1 !== remote.sha1) {
        return false;
    }
    return remote.sha256 === '' || local.sha256 === remote.sha256;
}

function statusCodeOf(error: unknown): number | undefined {
    if (typeof error !== 'object' || error === null || !('statusCode' in error)) {
        return undefined;
    }
    const statusCode: unknown = error.statusCode;
    return typeof statusCode === 'number' ? statusCode : undefined;
}
