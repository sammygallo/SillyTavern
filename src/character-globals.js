import path from 'node:path';
import fs from 'node:fs';
import { sync as writeFileAtomicSync } from 'write-file-atomic';
import sanitize from 'sanitize-filename';

import { GLOBAL_DATA_DIR } from './constants.js';

/**
 * Global character sharing.
 *
 * Global characters physically live under ${DATA_ROOT}/_global/characters/ — a
 * single source of truth that any authenticated user can read. Ownership and
 * visibility are tracked in ${DATA_ROOT}/_global/character-metadata.json.
 *
 * When a character is "global", it is moved from the owner's personal
 * characters directory into the global directory. Making it "personal" moves
 * it back into the caller's personal directory.
 *
 * This file centralizes the global-resolution logic so character endpoints
 * don't need to special-case it inline.
 */

const METADATA_FILE = 'character-metadata.json';
const GLOBAL_CHARACTERS_DIR = 'characters';
const GLOBAL_THUMBNAILS_DIR = 'thumbnails/avatar';

/**
 * @typedef {Object} CharacterMetadataEntry
 * @property {string} ownerHandle Handle of the user who owns this character.
 * @property {'global'|'personal'} visibility Current visibility.
 * @property {number} claimedAt Unix ms timestamp of when ownership was recorded.
 */

/**
 * @typedef {Record<string, CharacterMetadataEntry>} CharacterMetadataMap
 */

/**
 * Returns the absolute path to the global data root, creating it if needed.
 * @returns {string}
 */
export function getGlobalRoot() {
    const globalRoot = path.join(globalThis.DATA_ROOT, GLOBAL_DATA_DIR);
    if (!fs.existsSync(globalRoot)) {
        fs.mkdirSync(globalRoot, { recursive: true });
    }
    return globalRoot;
}

/**
 * Returns the absolute path to the global characters directory, creating it if needed.
 * @returns {string}
 */
export function getGlobalCharactersDir() {
    const dir = path.join(getGlobalRoot(), GLOBAL_CHARACTERS_DIR);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
    return dir;
}

/**
 * Returns the absolute path to the global avatar thumbnails directory, creating it if needed.
 * @returns {string}
 */
export function getGlobalThumbnailsDir() {
    const dir = path.join(getGlobalRoot(), GLOBAL_THUMBNAILS_DIR);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
    return dir;
}

/**
 * Returns the absolute path to the metadata file.
 * @returns {string}
 */
function getMetadataPath() {
    return path.join(getGlobalRoot(), METADATA_FILE);
}

/**
 * Reads the character metadata map from disk. Returns {} if missing or malformed.
 * @returns {CharacterMetadataMap}
 */
export function readMetadata() {
    const metadataPath = getMetadataPath();
    if (!fs.existsSync(metadataPath)) return {};
    try {
        const raw = fs.readFileSync(metadataPath, 'utf-8');
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
            return /** @type {CharacterMetadataMap} */ (parsed);
        }
        return {};
    } catch (err) {
        console.warn('Failed to read character metadata, starting fresh:', err);
        return {};
    }
}

/**
 * Writes the character metadata map to disk atomically.
 * @param {CharacterMetadataMap} metadata
 */
export function writeMetadata(metadata) {
    const metadataPath = getMetadataPath();
    const globalRoot = getGlobalRoot();
    if (!fs.existsSync(globalRoot)) {
        fs.mkdirSync(globalRoot, { recursive: true });
    }
    writeFileAtomicSync(metadataPath, JSON.stringify(metadata, null, 4), 'utf-8');
}

/**
 * Returns the metadata entry for a single character, or null if unknown.
 * @param {string} avatar Character filename (e.g. "Seraphina.png")
 * @returns {CharacterMetadataEntry | null}
 */
export function getEntry(avatar) {
    const map = readMetadata();
    return map[avatar] ?? null;
}

/**
 * Returns true if the named character is currently global.
 * @param {string} avatar Character filename.
 * @returns {boolean}
 */
export function isGlobal(avatar) {
    const entry = getEntry(avatar);
    if (!entry) return false;
    if (entry.visibility !== 'global') return false;
    // Verify the physical file exists in the global dir — otherwise the
    // metadata is stale (e.g. file deleted externally).
    const globalPath = path.join(getGlobalCharactersDir(), avatar);
    return fs.existsSync(globalPath);
}

/**
 * Resolves the on-disk path for a character. Global characters are checked
 * first; if not found, falls back to the requesting user's personal directory.
 *
 * The return shape lets callers know *which* scope the character lives in so
 * they can do follow-up work (thumbnail invalidation, chat lookups, etc.)
 * against the right directory set.
 *
 * @param {import('./users.js').UserDirectoryList} directories Caller's user directories.
 * @param {string} avatar Character filename (e.g. "Seraphina.png").
 * @returns {{ path: string, scope: 'global' | 'personal', exists: boolean }}
 */
export function resolveCharacterPath(directories, avatar) {
    const safe = sanitize(avatar);
    if (safe !== avatar) {
        return {
            path: path.join(directories.characters, avatar),
            scope: 'personal',
            exists: false,
        };
    }

    if (isGlobal(safe)) {
        const globalPath = path.join(getGlobalCharactersDir(), safe);
        return {
            path: globalPath,
            scope: 'global',
            exists: fs.existsSync(globalPath),
        };
    }

    const personalPath = path.join(directories.characters, safe);
    return {
        path: personalPath,
        scope: 'personal',
        exists: fs.existsSync(personalPath),
    };
}

/**
 * Lists the .png files in the global characters directory.
 * @returns {string[]}
 */
export function listGlobalCharacterFiles() {
    const dir = getGlobalCharactersDir();
    try {
        return fs.readdirSync(dir).filter(file => file.endsWith('.png'));
    } catch {
        return [];
    }
}

/**
 * Builds a pseudo "UserDirectoryList" shape pointing into the global dir.
 * This lets `processCharacter` (which reads characters + chats + thumbnails
 * from a directories object) operate on a global character without being
 * taught about the global scope. Chat metadata still comes from the caller's
 * personal chat directory since chats are always per-user.
 *
 * @param {import('./users.js').UserDirectoryList} userDirectories Caller's directories (used for chats + thumbnails).
 * @returns {import('./users.js').UserDirectoryList}
 */
export function makeGlobalScopedDirectories(userDirectories) {
    return {
        ...userDirectories,
        characters: getGlobalCharactersDir(),
        thumbnailsAvatar: getGlobalThumbnailsDir(),
    };
}

/**
 * Moves a character file between scopes and updates metadata.
 *
 * @param {object} params
 * @param {string} params.avatar Character filename (e.g. "Seraphina.png").
 * @param {'global'|'personal'} params.visibility Target visibility.
 * @param {string} params.ownerHandle Handle to record as owner.
 * @param {import('./users.js').UserDirectoryList} params.ownerDirectories Owner's personal directories (destination for personal, source for global).
 * @returns {{ moved: boolean, reason?: string }}
 */
export function setVisibility({ avatar, visibility, ownerHandle, ownerDirectories }) {
    const safe = sanitize(avatar);
    if (!safe || safe !== avatar) {
        return { moved: false, reason: 'invalid_filename' };
    }
    if (visibility !== 'global' && visibility !== 'personal') {
        return { moved: false, reason: 'invalid_visibility' };
    }

    const globalDir = getGlobalCharactersDir();
    const personalDir = ownerDirectories.characters;
    const globalPath = path.join(globalDir, safe);
    const personalPath = path.join(personalDir, safe);
    const metadata = readMetadata();

    if (visibility === 'global') {
        // Already global — just update metadata to ensure it's recorded.
        if (fs.existsSync(globalPath)) {
            metadata[safe] = {
                ownerHandle,
                visibility: 'global',
                claimedAt: metadata[safe]?.claimedAt ?? Date.now(),
            };
            writeMetadata(metadata);
            return { moved: false };
        }
        if (!fs.existsSync(personalPath)) {
            return { moved: false, reason: 'source_missing' };
        }
        // Move personal → global.
        try {
            fs.renameSync(personalPath, globalPath);
        } catch (err) {
            // Cross-device rename can fail — fall back to copy + unlink.
            try {
                fs.copyFileSync(personalPath, globalPath);
                fs.unlinkSync(personalPath);
            } catch (copyErr) {
                console.error('Failed to move character to global dir:', copyErr);
                return { moved: false, reason: 'move_failed' };
            }
        }
        metadata[safe] = {
            ownerHandle,
            visibility: 'global',
            claimedAt: metadata[safe]?.claimedAt ?? Date.now(),
        };
        writeMetadata(metadata);
        return { moved: true };
    }

    // visibility === 'personal'
    if (fs.existsSync(globalPath)) {
        // Move global → personal (caller's personal dir).
        if (!fs.existsSync(personalDir)) {
            fs.mkdirSync(personalDir, { recursive: true });
        }
        if (fs.existsSync(personalPath)) {
            return { moved: false, reason: 'destination_exists' };
        }
        try {
            fs.renameSync(globalPath, personalPath);
        } catch (err) {
            try {
                fs.copyFileSync(globalPath, personalPath);
                fs.unlinkSync(globalPath);
            } catch (copyErr) {
                console.error('Failed to move character back to personal dir:', copyErr);
                return { moved: false, reason: 'move_failed' };
            }
        }
    }
    // Record as personal (or drop the entry entirely — we drop, since personal
    // is the default and there's no need to persist an entry for it).
    delete metadata[safe];
    writeMetadata(metadata);
    return { moved: true };
}

/**
 * Removes the metadata entry for a character (used when a global character is deleted).
 * Does NOT touch the filesystem.
 * @param {string} avatar
 */
export function removeMetadataEntry(avatar) {
    const safe = sanitize(avatar);
    const metadata = readMetadata();
    if (metadata[safe]) {
        delete metadata[safe];
        writeMetadata(metadata);
    }
}

/**
 * Transfers ownership of a global character to another user. Metadata-only —
 * the PNG stays in `_global/characters/`. Returns a reason code so the caller
 * can map it to an HTTP status.
 *
 * @param {object} params
 * @param {string} params.avatar Character filename (e.g. "Seraphina.png").
 * @param {string} params.currentOwnerHandle Handle that must match the existing owner.
 * @param {string} params.newOwnerHandle Handle to record as the new owner.
 * @returns {{ ok: boolean, reason?: string }}
 */
export function transferOwnership({ avatar, currentOwnerHandle, newOwnerHandle }) {
    const safe = sanitize(avatar);
    if (!safe || safe !== avatar) {
        return { ok: false, reason: 'invalid_filename' };
    }
    if (!newOwnerHandle || typeof newOwnerHandle !== 'string') {
        return { ok: false, reason: 'invalid_recipient' };
    }

    const metadata = readMetadata();
    const entry = metadata[safe];
    if (!entry || entry.visibility !== 'global') {
        return { ok: false, reason: 'not_global' };
    }
    if (entry.ownerHandle !== currentOwnerHandle) {
        return { ok: false, reason: 'not_owner' };
    }
    if (newOwnerHandle === currentOwnerHandle) {
        return { ok: false, reason: 'same_owner' };
    }

    metadata[safe] = {
        ...entry,
        ownerHandle: newOwnerHandle,
        transferredAt: Date.now(),
        previousOwnerHandle: currentOwnerHandle,
    };
    writeMetadata(metadata);
    return { ok: true };
}

/**
 * Renames the metadata entry for a character (used when a global character is renamed).
 * @param {string} oldAvatar
 * @param {string} newAvatar
 */
export function renameMetadataEntry(oldAvatar, newAvatar) {
    const safeOld = sanitize(oldAvatar);
    const safeNew = sanitize(newAvatar);
    const metadata = readMetadata();
    if (metadata[safeOld]) {
        metadata[safeNew] = metadata[safeOld];
        delete metadata[safeOld];
        writeMetadata(metadata);
    }
}
