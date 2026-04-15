import storage from 'node-persist';

import { color } from './util.js';

/**
 * Permission Groups (Phase 10 of the multiuser system).
 *
 * Replaces the fixed 4-tier role ladder with custom permission groups. Every
 * user belongs to exactly one group; a group is a named set of permissions.
 *
 * The old `user.role` and `user.admin` fields are kept as deprecated shims on
 * the user record — they are rewritten from the current group whenever the
 * group changes, so the classic web UI and any external tooling that reads
 * `/me` keep working without modification. The backend does NOT read these
 * fields for auth decisions: only `user.groupId` is load-bearing.
 *
 * See also: /Users/sammy/.claude/plans/sparkling-drifting-graham.md
 */

// ---------------------------------------------------------------------------
// Permission vocabulary
// ---------------------------------------------------------------------------

/**
 * The master permission vocabulary, grouped by category.
 *
 * Category names are purely for UI rendering — the server sees a flat list of
 * strings. Adding a new permission here automatically:
 *   - makes it appear in the permission-group editor
 *   - makes it available for `requirePermission` checks
 *   - gets picked up by the default-group seeder (new perms are added to the
 *     Owner group only; all other groups must be edited explicitly to grant it)
 *
 * Tiered semantics:
 *   - `*:view`        — read-only access
 *   - `*:manage`      — full CRUD for a feature the user owns
 *   - `*:manage_global` — CRUD that affects other users or the server as a whole
 *   - `admin:*`       — operate on the user/group admin surface
 *   - `system:*`      — operate on the server/data itself
 *
 * @type {Readonly<Record<string, readonly string[]>>}
 */
export const PERMISSION_CATEGORIES = Object.freeze({
    'Chat & Generation': Object.freeze([
        'chat:read',              // list/open chats
        'chat:write',             // save chat changes (not the same as generation)
        'chat:delete',            // delete chats or messages
        'chat:import_export',     // import / export chat files
        'generation:use',         // umbrella: run any provider call
        'generation:image',       // cost-sensitive: image generation
        'generation:audio',       // cost-sensitive: TTS / paid voice
    ]),
    'Characters': Object.freeze([
        'character:view',
        'character:create',
        'character:edit',
        'character:delete',
        'character:import_export',
        'character:set_global',   // toggle a character to the shared global pool
    ]),
    'Groups & Personas': Object.freeze([
        'character_group:view',
        'character_group:manage',
        'persona:view',
        'persona:manage',
    ]),
    'World Info': Object.freeze([
        'worldinfo:view',
        'worldinfo:manage',
    ]),
    'Settings': Object.freeze([
        'settings:view',
        'settings:connection',
        'settings:api_keys',
        'settings:generation',
        'settings:appearance',
        'settings:global_secrets', // owner-only today: shared secrets file
    ]),
    'Extensions': Object.freeze([
        'extension:view',
        'extension:manage_personal',
        'extension:manage_global',
    ]),
    'Data Bank': Object.freeze([
        'databank:view',
        'databank:manage',
        'databank:manage_global',
    ]),
    'Automation': Object.freeze([
        'automation:quickreplies:manage',
        'automation:regex:manage',
        'automation:prompts:manage',
    ]),
    'Administration': Object.freeze([
        'admin:users:view',
        'admin:users:manage',         // create / edit / enable / disable / delete
        'admin:users:reset_password', // intentionally separate from users:manage
        'admin:users:set_group',      // assign a user to a group
        'admin:invitations:manage',
        'admin:groups:manage',        // CRUD permission groups (owner-only in practice)
        'admin:data_maid:manage',
        'admin:content_import',
    ]),
    'System': Object.freeze([
        'system:backup:self',
        'system:backup:others',
    ]),
});

/**
 * Flat list of every permission, derived from the category map.
 * @type {readonly string[]}
 */
export const PERMISSIONS = Object.freeze(
    Object.values(PERMISSION_CATEGORIES).flat(),
);

const PERMISSION_SET = new Set(PERMISSIONS);

/**
 * Returns true if `perm` is a known permission in the vocabulary.
 * @param {string} perm
 * @returns {boolean}
 */
export function isValidPermission(perm) {
    return typeof perm === 'string' && PERMISSION_SET.has(perm);
}

// ---------------------------------------------------------------------------
// Default permission groups
// ---------------------------------------------------------------------------

export const OWNER_GROUP_ID = 'owner-default';
export const ADMIN_GROUP_ID = 'admin-default';
export const CONTRIBUTOR_GROUP_ID = 'contributor-default';
export const END_USER_GROUP_ID = 'end-user-default';

/**
 * Permissions an Owner holds that an Admin does not. These are the
 * "affects the whole instance" powers that remain owner-only.
 */
const OWNER_ONLY_PERMISSIONS = new Set([
    'admin:groups:manage',
    'admin:users:reset_password',
    'admin:content_import',
    'settings:global_secrets',
    'character:set_global',
    'extension:manage_global',
    'databank:manage_global',
    'system:backup:others',
]);

/**
 * Permissions a Contributor holds. Mostly content creation plus self-service.
 */
const CONTRIBUTOR_PERMISSIONS = Object.freeze([
    'chat:read', 'chat:write', 'chat:delete', 'chat:import_export',
    'generation:use', 'generation:image', 'generation:audio',
    'character:view', 'character:create', 'character:edit',
    'character:delete', 'character:import_export',
    'character_group:view', 'character_group:manage',
    'persona:view', 'persona:manage',
    'worldinfo:view', 'worldinfo:manage',
    'settings:view',
    'extension:view', 'extension:manage_personal',
    'databank:view', 'databank:manage',
    'automation:quickreplies:manage',
    'automation:regex:manage',
    'automation:prompts:manage',
    'system:backup:self',
]);

/**
 * Permissions an End User holds. Read-heavy, can chat and manage their own persona.
 */
const END_USER_PERMISSIONS = Object.freeze([
    'chat:read', 'chat:write',
    'generation:use',
    'character:view',
    'persona:view', 'persona:manage',
    'databank:view',
    'settings:view',
    'system:backup:self',
]);

/**
 * Returns the Admin default permission set (derived: all perms minus owner-only).
 * @returns {string[]}
 */
function makeAdminPermissions() {
    return PERMISSIONS.filter(p => !OWNER_ONLY_PERMISSIONS.has(p));
}

/**
 * Seed definitions for the four default permission groups. These are the
 * groups created on first boot, and the targets of the role-to-group migration.
 *
 * - `owner-default` is `systemOwner: true`. Its permission set is permanently
 *   locked to the full vocabulary; any attempt to remove perms from it fails.
 * - The other three default groups are `system: true` (cannot be deleted) but
 *   their permission sets ARE editable — an admin can customize "what does
 *   Contributor mean in my instance" without creating a new group.
 *
 * @returns {Array<Partial<import('./permissions.js').PermissionGroup>>}
 */
function getDefaultGroupSeeds() {
    const now = Date.now();
    return [
        {
            id: OWNER_GROUP_ID,
            name: 'Owner',
            description: 'Full access to every permission. Cannot be deleted. '
                + 'Members of this group are the ultimate administrators of the instance.',
            permissions: [...PERMISSIONS],
            system: true,
            systemOwner: true,
            createdBy: null,
            createdAt: now,
            updatedAt: now,
        },
        {
            id: ADMIN_GROUP_ID,
            name: 'Admin',
            description: 'Manages users, invitations, and day-to-day operations. '
                + 'Cannot manage permission groups themselves, manage global secrets, '
                + 'or toggle global character visibility.',
            permissions: makeAdminPermissions(),
            system: true,
            systemOwner: false,
            createdBy: null,
            createdAt: now,
            updatedAt: now,
        },
        {
            id: CONTRIBUTOR_GROUP_ID,
            name: 'Contributor',
            description: 'Creates and edits characters, chats, personas, and world info. '
                + 'Can run the generation pipeline but cannot change instance-wide settings.',
            permissions: [...CONTRIBUTOR_PERMISSIONS],
            system: true,
            systemOwner: false,
            createdBy: null,
            createdAt: now,
            updatedAt: now,
        },
        {
            id: END_USER_GROUP_ID,
            name: 'End User',
            description: 'Can chat with characters and manage their own persona. '
                + 'Read-only access to characters created by others.',
            permissions: [...END_USER_PERMISSIONS],
            system: true,
            systemOwner: false,
            createdBy: null,
            createdAt: now,
            updatedAt: now,
        },
    ];
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * @typedef {Object} PermissionGroup
 * @property {string} id - Slug identifier, immutable after creation.
 * @property {string} name - Display name, editable.
 * @property {string} description - Human-readable description, editable.
 * @property {string[]} permissions - Flat list of permission strings.
 * @property {boolean} system - True for the four seeded defaults. Cannot be deleted.
 *   Permission set IS editable except when systemOwner is also true.
 * @property {boolean} systemOwner - True for exactly one group (OWNER_GROUP_ID).
 *   Permission set is permanently locked to the full vocabulary. Cannot be
 *   deleted. Must always have at least one enabled member.
 * @property {string|null} createdBy - Handle of creator. null for system groups.
 * @property {number} createdAt - Unix ms.
 * @property {number} updatedAt - Unix ms.
 */

// ---------------------------------------------------------------------------
// Storage (node-persist, prefix: `group:${id}`)
// ---------------------------------------------------------------------------

const GROUP_PREFIX = 'group:';

/**
 * @param {string} id
 * @returns {string}
 */
function groupKey(id) {
    return `${GROUP_PREFIX}${id}`;
}

/**
 * Returns all permission groups from storage, sorted by creation time.
 * @returns {Promise<PermissionGroup[]>}
 */
export async function getAllPermissionGroups() {
    const groups = await storage.values(x => x.key.startsWith(GROUP_PREFIX));
    return groups.sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0));
}

/**
 * Returns a permission group by id, or null if not found.
 * @param {string} id
 * @returns {Promise<PermissionGroup|null>}
 */
export async function getPermissionGroupById(id) {
    if (!id) return null;
    const group = await storage.getItem(groupKey(id));
    return group || null;
}

/**
 * Persists a permission group, updating `updatedAt`.
 * @param {PermissionGroup} group
 * @returns {Promise<void>}
 */
async function savePermissionGroup(group) {
    const withTimestamp = { ...group, updatedAt: Date.now() };
    await storage.setItem(groupKey(group.id), withTimestamp);
}

/**
 * Removes a permission group by id. Caller is responsible for safety rails.
 * @param {string} id
 * @returns {Promise<void>}
 */
async function removePermissionGroup(id) {
    await storage.removeItem(groupKey(id));
}

// ---------------------------------------------------------------------------
// Permission resolution
// ---------------------------------------------------------------------------

/**
 * In-memory cache for the "default-user is virtual owner when accounts
 * disabled" short-circuit. Populated on first call and refreshed only when
 * the cached value is stale by a minute — this isn't security-critical
 * because the frozen DEFAULT_USER object always resolves to owner anyway.
 */
const ALL_PERMS_ARRAY = Object.freeze([...PERMISSIONS]);

/**
 * Resolves the permission set for a user.
 *
 * Resolution order:
 *   1. If user has a valid groupId that exists in storage → that group's perms.
 *   2. If user is the frozen DEFAULT_USER (accounts disabled) → all perms.
 *   3. Legacy shim: if user has admin:true OR role === 'admin'/'owner' →
 *      ADMIN_GROUP_ID perms (or owner perms if role === 'owner').
 *   4. Default: END_USER_GROUP_ID perms, or empty set if even that is missing.
 *
 * Never throws. A user with a dangling groupId (group was deleted) falls
 * through to the legacy shim; this should only happen if migration hasn't
 * run yet, since the migration re-anchors dangling groupIds.
 *
 * @param {{ handle: string, groupId?: string, admin?: boolean, role?: string }} user
 * @returns {Promise<string[]>}
 */
export async function getUserPermissions(user) {
    if (!user) return [];

    if (user.groupId) {
        const group = await getPermissionGroupById(user.groupId);
        if (group && Array.isArray(group.permissions)) {
            return group.permissions;
        }
    }

    // Short-circuit for the frozen DEFAULT_USER when accounts are disabled.
    // DEFAULT_USER is always admin:true, role:'owner' and never gets migrated.
    if (user.handle === 'default-user' && user.admin === true) {
        return [...ALL_PERMS_ARRAY];
    }

    // Legacy shim path: resolve via the old admin/role fields.
    if (user.role === 'owner' || (user.admin === true && !user.role)) {
        const owner = await getPermissionGroupById(OWNER_GROUP_ID);
        if (owner) return owner.permissions;
        return [...ALL_PERMS_ARRAY];
    }
    if (user.role === 'admin' || user.admin === true) {
        const admin = await getPermissionGroupById(ADMIN_GROUP_ID);
        if (admin) return admin.permissions;
    }
    if (user.role === 'contributor') {
        const contributor = await getPermissionGroupById(CONTRIBUTOR_GROUP_ID);
        if (contributor) return contributor.permissions;
    }
    const endUser = await getPermissionGroupById(END_USER_GROUP_ID);
    if (endUser) return endUser.permissions;
    return [];
}

/**
 * Synchronous permission check against a pre-resolved permission array.
 * Use this inside middleware after a single `getUserPermissions` call.
 * @param {string[]} permissions
 * @param {string} required
 * @returns {boolean}
 */
export function hasPermissionInSet(permissions, required) {
    return Array.isArray(permissions) && permissions.includes(required);
}

/**
 * Async permission check against a user profile.
 * @param {{ handle: string, groupId?: string, admin?: boolean, role?: string }} user
 * @param {string} required
 * @returns {Promise<boolean>}
 */
export async function hasPermission(user, required) {
    const perms = await getUserPermissions(user);
    return hasPermissionInSet(perms, required);
}

/**
 * Checks that every required permission is present.
 * @param {{ handle: string, groupId?: string, admin?: boolean, role?: string }} user
 * @param  {...string} required
 * @returns {Promise<boolean>}
 */
export async function hasAllPermissions(user, ...required) {
    const perms = await getUserPermissions(user);
    return required.every(p => hasPermissionInSet(perms, p));
}

/**
 * Checks that at least one required permission is present.
 * @param {{ handle: string, groupId?: string, admin?: boolean, role?: string }} user
 * @param  {...string} required
 * @returns {Promise<boolean>}
 */
export async function hasAnyPermission(user, ...required) {
    const perms = await getUserPermissions(user);
    return required.some(p => hasPermissionInSet(perms, p));
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

/**
 * Express middleware: the authenticated user must hold ALL of the required
 * permissions. For OR-semantics use `requireAnyPermission`.
 *
 * Replaces `requireMinRole` at all enforcement sites.
 *
 * @param  {...string} required
 * @returns {import('express').RequestHandler}
 */
export function requirePermission(...required) {
    if (required.length === 0) {
        throw new Error('requirePermission called without any permissions');
    }
    for (const p of required) {
        if (!isValidPermission(p)) {
            throw new Error(`requirePermission: unknown permission '${p}'`);
        }
    }

    return async function (request, response, next) {
        if (!request.user) {
            return response.sendStatus(403);
        }
        try {
            const perms = await getUserPermissions(request.user.profile);
            const missing = required.filter(p => !hasPermissionInSet(perms, p));
            if (missing.length > 0) {
                console.warn(
                    `Unauthorized: user ${request.user.profile.handle} tried to access `
                    + `${request.originalUrl}, missing permission(s): [${missing.join(', ')}]`,
                );
                return response.sendStatus(403);
            }
            return next();
        } catch (error) {
            console.error('Permission check failed:', error);
            return response.sendStatus(500);
        }
    };
}

/**
 * Express middleware: the authenticated user must hold ANY ONE of the
 * required permissions.
 * @param  {...string} required
 * @returns {import('express').RequestHandler}
 */
export function requireAnyPermission(...required) {
    if (required.length === 0) {
        throw new Error('requireAnyPermission called without any permissions');
    }
    for (const p of required) {
        if (!isValidPermission(p)) {
            throw new Error(`requireAnyPermission: unknown permission '${p}'`);
        }
    }

    return async function (request, response, next) {
        if (!request.user) {
            return response.sendStatus(403);
        }
        try {
            const perms = await getUserPermissions(request.user.profile);
            const hasAny = required.some(p => hasPermissionInSet(perms, p));
            if (!hasAny) {
                console.warn(
                    `Unauthorized: user ${request.user.profile.handle} tried to access `
                    + `${request.originalUrl}, needs one of: [${required.join(', ')}]`,
                );
                return response.sendStatus(403);
            }
            return next();
        } catch (error) {
            console.error('Permission check failed:', error);
            return response.sendStatus(500);
        }
    };
}

// ---------------------------------------------------------------------------
// Safety-rail helpers
// ---------------------------------------------------------------------------

/**
 * Returns the total number of ENABLED users currently in the given group.
 * Used by the systemOwner-anchor invariant: at least one enabled user must
 * always be a member of the systemOwner group.
 *
 * @param {string} groupId
 * @returns {Promise<number>}
 */
export async function countEnabledMembersOfGroup(groupId) {
    // Avoid a circular import: read the user prefix directly.
    const KEY_PREFIX = 'user:';
    const users = await storage.values(x => x.key.startsWith(KEY_PREFIX));
    let count = 0;
    for (const u of users) {
        if (u.groupId === groupId && u.enabled !== false) {
            count += 1;
        }
    }
    return count;
}

/**
 * Returns the total number of users (enabled or disabled) currently in the
 * given group. Used by "cannot delete a group with members" rail.
 *
 * @param {string} groupId
 * @returns {Promise<number>}
 */
export async function countAllMembersOfGroup(groupId) {
    const KEY_PREFIX = 'user:';
    const users = await storage.values(x => x.key.startsWith(KEY_PREFIX));
    let count = 0;
    for (const u of users) {
        if (u.groupId === groupId) count += 1;
    }
    return count;
}

/**
 * Returns the systemOwner group, loading it from storage. Throws if missing
 * (this would indicate a corrupted install — the seed migration must always
 * produce exactly one systemOwner group).
 * @returns {Promise<PermissionGroup>}
 */
async function getSystemOwnerGroup() {
    const all = await getAllPermissionGroups();
    const owner = all.find(g => g.systemOwner === true);
    if (!owner) {
        throw new Error(
            'No systemOwner group exists — the permissions subsystem is in an '
            + 'inconsistent state. Restart the server to re-run the seed migration.',
        );
    }
    return owner;
}

/**
 * Validates that the systemOwner group would still have at least one enabled
 * member after a proposed mutation. Throws an Error (with a `.status` property
 * for the Express layer to pick up) if the invariant would be violated.
 *
 * @param {object} params
 * @param {'delete-user' | 'disable-user' | 'move-user-out'} params.operation
 * @param {string} params.targetHandle  Handle of the user being mutated.
 * @returns {Promise<void>}
 */
export async function assertSystemOwnerInvariant({ operation, targetHandle }) {
    const KEY_PREFIX = 'user:';
    const ownerGroup = await getSystemOwnerGroup();
    const users = await storage.values(x => x.key.startsWith(KEY_PREFIX));

    // Count enabled members of the owner group, excluding the target (since
    // the proposed mutation would remove them from the count).
    let remaining = 0;
    for (const u of users) {
        if (u.groupId !== ownerGroup.id) continue;
        if (u.handle === targetHandle) continue;
        if (u.enabled === false) continue;
        remaining += 1;
    }

    if (remaining < 1) {
        const err = new Error(
            `Cannot leave the system without an enabled owner (operation: ${operation})`,
        );
        // @ts-ignore — attaching HTTP status for the caller
        err.status = 409;
        throw err;
    }
}

/**
 * Checks that the `actor` holds at least every permission in `targetGroup`.
 * Used to prevent privilege escalation via group assignment:
 *   - POST /users/set-group must not let a non-owner hand someone else a more
 *     powerful group than the actor themselves holds.
 *   - POST /users/create likewise.
 *   - POST /invitations/create likewise — the inviter can only offer a group
 *     whose permissions are a subset of their own.
 *
 * Computed from the actor's CURRENT permissions — not from any pending edit.
 *
 * @param {{ handle: string, groupId?: string, admin?: boolean, role?: string }} actor
 * @param {PermissionGroup} targetGroup
 * @returns {Promise<boolean>}
 */
export async function canAssignGroup(actor, targetGroup) {
    if (!targetGroup || !Array.isArray(targetGroup.permissions)) return false;
    const actorPerms = await getUserPermissions(actor);
    return targetGroup.permissions.every(p => actorPerms.includes(p));
}

/**
 * Checks that an edit to a group does not add any permission the actor
 * doesn't currently hold. Required because an actor in the group being
 * edited could otherwise escalate their own permissions.
 *
 * @param {{ handle: string, groupId?: string, admin?: boolean, role?: string }} actor
 * @param {PermissionGroup} oldGroup  The group as currently stored.
 * @param {string[]} newPermissions   The proposed permission set.
 * @returns {Promise<{ ok: boolean, reason?: string }>}
 */
export async function canEditGroup(actor, oldGroup, newPermissions) {
    const actorPerms = await getUserPermissions(actor);
    const addedPerms = newPermissions.filter(p => !oldGroup.permissions.includes(p));
    const escalating = addedPerms.filter(p => !actorPerms.includes(p));
    if (escalating.length > 0) {
        return {
            ok: false,
            reason: `Cannot add permissions to a group that you don't hold yourself: [${escalating.join(', ')}]`,
        };
    }
    return { ok: true };
}

// ---------------------------------------------------------------------------
// Mutation mutex
// ---------------------------------------------------------------------------

/**
 * Serializes group mutations so that two concurrent edits cannot bypass
 * privilege-escalation or systemOwner-invariant checks by racing each other.
 *
 * Usage:
 *   await mutateWithGroupLock(async () => {
 *       // read, validate, write — atomic w.r.t. other lock holders
 *   });
 *
 * @type {Promise<any>}
 */
let groupMutationChain = Promise.resolve();

/**
 * @template T
 * @param {() => Promise<T>} fn
 * @returns {Promise<T>}
 */
export function mutateWithGroupLock(fn) {
    const next = groupMutationChain.then(fn, fn);
    groupMutationChain = next.catch(() => { /* swallow so next caller can proceed */ });
    return next;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/**
 * Validates the shape of a permission-group create/update payload. Does NOT
 * enforce privilege-escalation or systemOwner rules — those are higher-level
 * checks in the endpoint handler.
 *
 * @param {object} input
 * @param {'create' | 'update'} mode
 * @returns {{ ok: true, value: { name: string, description: string, permissions: string[] } } | { ok: false, error: string }}
 */
export function validateGroupInput(input, mode) {
    if (!input || typeof input !== 'object') {
        return { ok: false, error: 'Body is required' };
    }

    const name = typeof input.name === 'string' ? input.name.trim() : '';
    if (mode === 'create' && !name) {
        return { ok: false, error: 'name is required' };
    }
    if (name.length > 80) {
        return { ok: false, error: 'name is too long (max 80 chars)' };
    }

    const description = typeof input.description === 'string' ? input.description.trim() : '';
    if (description.length > 500) {
        return { ok: false, error: 'description is too long (max 500 chars)' };
    }

    if (!Array.isArray(input.permissions)) {
        return { ok: false, error: 'permissions must be an array' };
    }
    const seen = new Set();
    const permissions = [];
    for (const p of input.permissions) {
        if (typeof p !== 'string') {
            return { ok: false, error: `permissions must be strings (got ${typeof p})` };
        }
        if (!isValidPermission(p)) {
            return { ok: false, error: `unknown permission '${p}'` };
        }
        if (seen.has(p)) continue;
        seen.add(p);
        permissions.push(p);
    }

    return { ok: true, value: { name, description, permissions } };
}

/**
 * Generates a slug-like id from a display name. Ensures uniqueness by
 * appending a short random suffix when necessary.
 * @param {string} name
 * @returns {Promise<string>}
 */
export async function generateGroupId(name) {
    const base = String(name || 'group')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 48) || 'group';

    const existing = await getAllPermissionGroups();
    const taken = new Set(existing.map(g => g.id));

    if (!taken.has(base)) return base;

    for (let i = 2; i <= 99; i++) {
        const attempt = `${base}-${i}`;
        if (!taken.has(attempt)) return attempt;
    }
    // Fallback to random suffix
    const { randomBytes } = await import('node:crypto');
    return `${base}-${randomBytes(3).toString('hex')}`;
}

// ---------------------------------------------------------------------------
// Group mutations (called from the endpoint router, all go through the lock)
// ---------------------------------------------------------------------------

/**
 * Creates a new permission group. Caller must already have verified that the
 * actor holds `admin:groups:manage` and that the target permissions are a
 * subset of the actor's own permissions.
 *
 * @param {object} params
 * @param {string} params.id
 * @param {string} params.name
 * @param {string} params.description
 * @param {string[]} params.permissions
 * @param {string} params.createdByHandle
 * @returns {Promise<PermissionGroup>}
 */
export async function createPermissionGroup({ id, name, description, permissions, createdByHandle }) {
    return mutateWithGroupLock(async () => {
        const existing = await getPermissionGroupById(id);
        if (existing) {
            const err = new Error(`Group '${id}' already exists`);
            // @ts-ignore
            err.status = 409;
            throw err;
        }
        const now = Date.now();
        /** @type {PermissionGroup} */
        const group = {
            id,
            name,
            description,
            permissions: [...permissions],
            system: false,
            systemOwner: false,
            createdBy: createdByHandle,
            createdAt: now,
            updatedAt: now,
        };
        await savePermissionGroup(group);
        return group;
    });
}

/**
 * Updates an existing permission group.
 *
 * Rules enforced here (independent of the caller's own privilege check):
 *   - systemOwner groups: can edit `name` and `description` only. Permissions
 *     are locked to the full vocabulary. `id`, `system`, and `systemOwner`
 *     flags can never change.
 *   - System groups that are NOT systemOwner: can edit everything except
 *     `id`, `system`, and `systemOwner`.
 *   - Custom groups: can edit everything except `id`.
 *
 * @param {object} params
 * @param {string} params.id
 * @param {{ name?: string, description?: string, permissions?: string[] }} params.patch
 * @returns {Promise<PermissionGroup>}
 */
export async function updatePermissionGroup({ id, patch }) {
    return mutateWithGroupLock(async () => {
        const group = await getPermissionGroupById(id);
        if (!group) {
            const err = new Error(`Group '${id}' not found`);
            // @ts-ignore
            err.status = 404;
            throw err;
        }

        const updated = { ...group };
        if (typeof patch.name === 'string') updated.name = patch.name.trim();
        if (typeof patch.description === 'string') updated.description = patch.description.trim();

        if (Array.isArray(patch.permissions)) {
            if (group.systemOwner) {
                // systemOwner permission set is locked — ignore any change and
                // keep the full vocabulary. We don't error here because the
                // UI might send the same full list; we just make it a no-op.
                updated.permissions = [...PERMISSIONS];
            } else {
                updated.permissions = [...patch.permissions];
            }
        } else if (group.systemOwner) {
            // Defensive: even if patch doesn't touch permissions, keep the
            // systemOwner group anchored to the full vocabulary.
            updated.permissions = [...PERMISSIONS];
        }

        await savePermissionGroup(updated);
        return updated;
    });
}

/**
 * Deletes a permission group. Fails if it's systemOwner or has members.
 *
 * @param {string} id
 * @returns {Promise<void>}
 */
export async function deletePermissionGroup(id) {
    return mutateWithGroupLock(async () => {
        const group = await getPermissionGroupById(id);
        if (!group) {
            const err = new Error(`Group '${id}' not found`);
            // @ts-ignore
            err.status = 404;
            throw err;
        }
        if (group.systemOwner) {
            const err = new Error('Cannot delete the systemOwner group');
            // @ts-ignore
            err.status = 403;
            throw err;
        }
        if (group.system) {
            const err = new Error('Cannot delete a system group');
            // @ts-ignore
            err.status = 403;
            throw err;
        }
        const memberCount = await countAllMembersOfGroup(id);
        if (memberCount > 0) {
            const err = new Error(
                `Cannot delete group '${id}': it still has ${memberCount} member(s). `
                + 'Reassign them to a different group first.',
            );
            // @ts-ignore
            err.status = 409;
            throw err;
        }
        await removePermissionGroup(id);
    });
}

// ---------------------------------------------------------------------------
// Legacy shim helpers
// ---------------------------------------------------------------------------

/**
 * Derives the legacy `admin` boolean and `role` string from a user's current
 * group. Called by `syncLegacyShims(user)` in users.js whenever a user's
 * group changes, so the classic public/ UI and external tooling keep working.
 *
 * @param {string[]} permissions  The user's current resolved permission set.
 * @returns {{ admin: boolean, role: string }}
 */
export function deriveLegacyShims(permissions) {
    if (!Array.isArray(permissions)) {
        return { admin: false, role: 'end_user' };
    }
    const set = new Set(permissions);
    // Owner shim: has admin:groups:manage (owner-only in practice).
    if (set.has('admin:groups:manage')) {
        return { admin: true, role: 'owner' };
    }
    // Admin shim: has admin:users:manage.
    if (set.has('admin:users:manage')) {
        return { admin: true, role: 'admin' };
    }
    // Contributor shim: has character creation rights.
    if (set.has('character:create') || set.has('character:edit')) {
        return { admin: false, role: 'contributor' };
    }
    return { admin: false, role: 'end_user' };
}

/**
 * Maps a legacy role string to the corresponding default group id. Used by
 * the migration and by the transitional `/users/create` fallback when a
 * caller posts the old `{ role, admin }` shape.
 *
 * @param {string|undefined} role
 * @param {boolean|undefined} admin
 * @returns {string} A default group id.
 */
export function legacyRoleToGroupId(role, admin) {
    switch (role) {
        case 'owner': return OWNER_GROUP_ID;
        case 'admin': return ADMIN_GROUP_ID;
        case 'contributor': return CONTRIBUTOR_GROUP_ID;
        case 'end_user': return END_USER_GROUP_ID;
    }
    if (admin === true) return ADMIN_GROUP_ID;
    return END_USER_GROUP_ID;
}

// ---------------------------------------------------------------------------
// Initialization (called from users.js:initUserStorage)
// ---------------------------------------------------------------------------

/**
 * Seeds the default permission groups if storage is empty, and migrates any
 * existing users from the old role-based model onto the new groupId model.
 *
 * Idempotent: safe to call on every boot. A user that already has a valid
 * groupId referencing an existing group is not touched.
 *
 * Must be called AFTER `migrateUsersToRoles` (the role migration), so that
 * every user has a canonical `role` field to read from.
 *
 * @returns {Promise<void>}
 */
export async function initPermissionsAndMigrate() {
    await seedDefaultGroupsIfMissing();
    await migrateUsersToGroups();
    await verifySystemOwnerAnchor();
}

/**
 * Writes the four default groups to storage if they are not already there.
 * Each seed is only inserted if the id is missing — if an admin has already
 * edited (e.g.) the Admin group, we don't clobber their customization.
 */
async function seedDefaultGroupsIfMissing() {
    const seeds = getDefaultGroupSeeds();
    let seeded = 0;
    for (const seed of seeds) {
        const existing = await getPermissionGroupById(seed.id);
        if (existing) continue;
        await storage.setItem(groupKey(seed.id), seed);
        seeded += 1;
        console.log(color.green(`[Permissions] Seeded default group: ${seed.id}`));
    }
    if (seeded === 0) {
        // Quiet success — normal case on every boot after the first.
    }
}

/**
 * For every user in storage, ensures a valid `groupId` is set. Mapping:
 *   - If user already has a valid groupId referencing an existing group → skip.
 *   - Else map from user.role: owner/admin/contributor/end_user → default group.
 *   - Else if user.admin is true → admin-default.
 *   - Else → end-user-default.
 *
 * Also refreshes `user.admin` and `user.role` shims from the group so
 * downstream readers stay consistent.
 *
 * @returns {Promise<void>}
 */
async function migrateUsersToGroups() {
    const KEY_PREFIX = 'user:';
    const users = await storage.values(x => x.key.startsWith(KEY_PREFIX));

    for (const user of users) {
        // Skip if already migrated and the group still exists.
        if (user.groupId) {
            const existing = await getPermissionGroupById(user.groupId);
            if (existing) continue;
            console.warn(
                `[Permissions] User '${user.handle}' has dangling groupId '${user.groupId}', `
                + 'remapping from legacy role.',
            );
        }

        const targetGroupId = legacyRoleToGroupId(user.role, user.admin);
        user.groupId = targetGroupId;

        // Refresh shims from the freshly-assigned group so `/me` is consistent
        // even on the very first boot after upgrade.
        const targetGroup = await getPermissionGroupById(targetGroupId);
        const perms = targetGroup?.permissions ?? [];
        const shims = deriveLegacyShims(perms);
        user.admin = shims.admin;
        user.role = shims.role;

        await storage.setItem(`${KEY_PREFIX}${user.handle}`, user);
        console.log(
            color.green(
                `[Permissions] Migrated user '${user.handle}' to group: ${targetGroupId}`,
            ),
        );
    }
}

/**
 * Verifies that at least one enabled user is in the systemOwner group. If
 * not, logs a FATAL warning — the admin must manually recover.
 */
async function verifySystemOwnerAnchor() {
    const KEY_PREFIX = 'user:';
    const ownerGroup = await getPermissionGroupById(OWNER_GROUP_ID);
    if (!ownerGroup) {
        console.error(color.red('[Permissions] FATAL: owner-default group missing after seed'));
        return;
    }
    const users = await storage.values(x => x.key.startsWith(KEY_PREFIX));
    const enabledOwners = users.filter(u => u.groupId === OWNER_GROUP_ID && u.enabled !== false);
    if (enabledOwners.length === 0) {
        console.error(color.red(
            '[Permissions] WARNING: no enabled user is a member of the owner-default group. '
            + 'The system has no administrator. Set OWNER_HANDLE + OWNER_PASSWORD and restart, '
            + 'or manually edit a user record to re-anchor the instance.',
        ));
    }
}
