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

/**
 * Verifies a downloaded file against Artifactory checksums.
 * HEAD checksum headers are used first. A non-auth HEAD failure, or a HEAD
 * response without MD5 and SHA1, falls back to the Artifactory storage API.
 * The file is deleted when verification fails.
 */
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
                `Checksum verification failed for getFrogbot.sh. Remote md5=${remote.md5} sha1=${remote.sha1} sha256=${remote.sha256}. Local md5=${local.md5} sha1=${local.sha1} sha256=${local.sha256}.`,
            );
        }
    } catch (error) {
        if (existsSync(filePath)) {
            unlinkSync(filePath);
        }
        throw error;
    }
}

async function loadRemoteChecksums(artifactUrl: string, authorization: string): Promise<RemoteChecksums> {
    const headers: OutgoingHttpHeaders = authorizationHeaders(authorization);
    const client: HttpClient = new HttpClient();
    try {
        const response: HttpClientResponse = await client.request('HEAD', artifactUrl, null, headers);
        const remote: RemoteChecksums = checksumsFromHeaders(response.message.headers);
        if (remote.md5 && remote.sha1) {
            return remote;
        }
        core.debug('Checksum headers not returned by HEAD; using Artifactory Storage API.');
    } catch (error) {
        const status: number | undefined = statusCodeOf(error);
        if (status === 401 || status === 403) {
            throw new Error(`Artifactory rejected the getFrogbot.sh checksum request (${status}). Check JF_ACCESS_TOKEN or JF_USER/JF_PASSWORD.`);
        }
        core.debug('Checksum HEAD failed; using Artifactory Storage API.');
    }

    const storageUrl: string = artifactUrlToStorageUrl(artifactUrl);
    const response: HttpClientResponse = await client.request('GET', storageUrl, null, headers);
    const body: string = await response.readBody();
    return checksumsFromStorage(body);
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
