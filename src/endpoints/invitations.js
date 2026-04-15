import { randomUUID, randomBytes } from 'node:crypto';

import storage from 'node-persist';
import express from 'express';
import lodash from 'lodash';

import { checkForNewContent, CONTENT_TYPES } from './content-manager.js';
import {
    toKey,
    getAllUserHandles,
    getPasswordSalt,
    getPasswordHash,
    getUserDirectories,
    ensurePublicDirectoriesExist,
} from '../users.js';
import {
    requirePermission,
    getPermissionGroupById,
    canAssignGroup,
    deriveLegacyShims,
    legacyRoleToGroupId,
    END_USER_GROUP_ID,
} from '../permissions.js';

export const router = express.Router();

const INVITE_PREFIX = 'invite:';

/**
 * @typedef {object} Invitation
 * @property {string} id
 * @property {string} token
 * @property {string} groupId  - Permission group id to assign on accept.
 * @property {string} [role]   - @deprecated Shim for pre-groups invitations.
 * @property {string} label
 * @property {string} createdBy
 * @property {number} createdAt
 * @property {number|null} expiresAt
 * @property {string|null} usedBy
 * @property {number|null} usedAt
 * @property {'pending'|'accepted'|'revoked'} status
 */

/**
 * @param {string} id
 * @returns {string}
 */
function inviteKey(id) {
    return `${INVITE_PREFIX}${id}`;
}

/**
 * @returns {Promise<Invitation[]>}
 */
async function getAllInvitations() {
    /** @type {Invitation[]} */
    const raw = await storage.values(x => x.key.startsWith(INVITE_PREFIX));
    // In-flight migration: if a stored invitation only has `role`, synthesize
    // a `groupId` at read time so the rest of the code can assume groupId is
    // always present.
    return raw.map(inv => {
        if (!inv.groupId && inv.role) {
            return { ...inv, groupId: legacyRoleToGroupId(inv.role, undefined) };
        }
        return inv;
    });
}

// POST /api/invitations/create — requires admin:invitations:manage
router.post('/create', requirePermission('admin:invitations:manage'), async (request, response) => {
    try {
        // Determine target groupId: prefer explicit `groupId`, fall back to
        // legacy `role` shape. Default to end-user-default.
        let targetGroupId = '';
        if (typeof request.body.groupId === 'string' && request.body.groupId) {
            targetGroupId = request.body.groupId;
        } else if (request.body.role) {
            console.warn(
                `[Permissions] Deprecated: /invitations/create called with { role: '${request.body.role}' } — `
                + 'update caller to send { groupId } instead.',
            );
            targetGroupId = legacyRoleToGroupId(request.body.role, undefined);
        } else {
            targetGroupId = END_USER_GROUP_ID;
        }

        const targetGroup = await getPermissionGroupById(targetGroupId);
        if (!targetGroup) {
            return response.status(400).json({ error: `Unknown group: ${targetGroupId}` });
        }

        // Privilege guard: inviter must hold every permission they're offering.
        const allowed = await canAssignGroup(request.user.profile, targetGroup);
        if (!allowed) {
            return response.status(403).json({
                error: `Cannot invite to group '${targetGroup.id}' — it contains permissions you don't hold`,
            });
        }

        const label = String(request.body.label || '').trim().slice(0, 200);
        const expiresIn = request.body.expiresIn; // hours, optional
        const expiresAt = expiresIn ? Date.now() + Number(expiresIn) * 60 * 60 * 1000 : null;

        // Derive a legacy role shim so older clients reading the invitation
        // record still see something meaningful in the `role` field.
        const shims = deriveLegacyShims(targetGroup.permissions);

        /** @type {Invitation} */
        const invite = {
            id: randomUUID(),
            token: randomBytes(32).toString('hex'),
            groupId: targetGroup.id,
            role: shims.role,
            label,
            createdBy: request.user.profile.handle,
            createdAt: Date.now(),
            expiresAt,
            usedBy: null,
            usedAt: null,
            status: 'pending',
        };

        await storage.setItem(inviteKey(invite.id), invite);
        return response.json(invite);
    } catch (error) {
        console.error('Create invitation failed:', error);
        return response.sendStatus(500);
    }
});

// POST /api/invitations/list — requires admin:invitations:manage
router.post('/list', requirePermission('admin:invitations:manage'), async (_request, response) => {
    try {
        const invites = await getAllInvitations();
        // Sort newest first
        invites.sort((a, b) => b.createdAt - a.createdAt);
        return response.json(invites);
    } catch (error) {
        console.error('List invitations failed:', error);
        return response.sendStatus(500);
    }
});

// POST /api/invitations/revoke — requires admin:invitations:manage
router.post('/revoke', requirePermission('admin:invitations:manage'), async (request, response) => {
    try {
        const { id } = request.body;
        if (!id) {
            return response.status(400).json({ error: 'Missing id' });
        }

        /** @type {Invitation|undefined} */
        const invite = await storage.getItem(inviteKey(id));
        if (!invite) {
            return response.status(404).json({ error: 'Invitation not found' });
        }
        if (invite.status !== 'pending') {
            return response.status(409).json({ error: `Invitation is already ${invite.status}` });
        }

        invite.status = 'revoked';
        await storage.setItem(inviteKey(id), invite);
        return response.json(invite);
    } catch (error) {
        console.error('Revoke invitation failed:', error);
        return response.sendStatus(500);
    }
});

// POST /api/invitations/delete — requires admin:invitations:manage
router.post('/delete', requirePermission('admin:invitations:manage'), async (request, response) => {
    try {
        const { id } = request.body;
        if (!id) {
            return response.status(400).json({ error: 'Missing id' });
        }

        /** @type {Invitation|undefined} */
        const invite = await storage.getItem(inviteKey(id));
        if (!invite) {
            return response.status(404).json({ error: 'Invitation not found' });
        }

        await storage.removeItem(inviteKey(id));
        return response.json({ id });
    } catch (error) {
        console.error('Delete invitation failed:', error);
        return response.sendStatus(500);
    }
});

// GET /api/invitations/validate/:token — public
router.get('/validate/:token', async (request, response) => {
    try {
        const { token } = request.params;
        const invites = await getAllInvitations();
        const invite = invites.find(i => i.token === token);

        if (!invite) {
            return response.status(404).json({ valid: false, error: 'Invalid invite link' });
        }
        if (invite.status !== 'pending') {
            return response.status(410).json({ valid: false, error: `Invitation has been ${invite.status}` });
        }
        if (invite.expiresAt && Date.now() > invite.expiresAt) {
            return response.status(410).json({ valid: false, error: 'Invitation has expired' });
        }

        // Re-verify the group still exists and still has permissions.
        // Otherwise an invite pointing at a deleted group would create a
        // zero-permission user.
        const targetGroup = await getPermissionGroupById(invite.groupId);
        if (!targetGroup || !Array.isArray(targetGroup.permissions)) {
            return response.status(410).json({
                valid: false,
                error: 'The group referenced by this invitation no longer exists',
            });
        }

        return response.json({
            valid: true,
            groupId: invite.groupId,
            groupName: targetGroup.name,
            // Legacy shim for older frontends that read `role` off the response.
            role: invite.role ?? deriveLegacyShims(targetGroup.permissions).role,
            label: invite.label,
        });
    } catch (error) {
        console.error('Validate invitation failed:', error);
        return response.sendStatus(500);
    }
});

// POST /api/invitations/accept — public (no session required)
router.post('/accept', async (request, response) => {
    try {
        const { token, handle: rawHandle, name: rawName, password } = request.body;
        if (!token || !rawHandle || !rawName) {
            return response.status(400).json({ error: 'Missing required fields' });
        }

        // Validate the token
        const invites = await getAllInvitations();
        const invite = invites.find(i => i.token === token);

        if (!invite) {
            return response.status(404).json({ error: 'Invalid invite link' });
        }
        if (invite.status !== 'pending') {
            return response.status(410).json({ error: `Invitation has been ${invite.status}` });
        }
        if (invite.expiresAt && Date.now() > invite.expiresAt) {
            return response.status(410).json({ error: 'Invitation has expired' });
        }

        // Re-verify the target group. Snapshot semantics: we take the group
        // *as it exists now*, not as it existed when the invitation was created.
        const targetGroup = await getPermissionGroupById(invite.groupId);
        if (!targetGroup || !Array.isArray(targetGroup.permissions)) {
            return response.status(410).json({
                error: 'The group referenced by this invitation no longer exists',
            });
        }

        // Normalise handle
        const handle = lodash.kebabCase(String(rawHandle).toLowerCase().trim());
        if (!handle) {
            return response.status(400).json({ error: 'Invalid handle' });
        }

        const handles = await getAllUserHandles();
        if (handles.some(h => h === handle)) {
            return response.status(409).json({ error: 'Username already taken' });
        }

        const salt = getPasswordSalt();
        const passwordHash = password ? getPasswordHash(password, salt) : '';

        const shims = deriveLegacyShims(targetGroup.permissions);

        const newUser = {
            handle,
            name: String(rawName).trim().slice(0, 100) || 'Anonymous',
            created: Date.now(),
            password: passwordHash,
            salt,
            groupId: targetGroup.id,
            admin: shims.admin,
            role: shims.role,
            enabled: true,
        };

        await storage.setItem(toKey(handle), newUser);

        // Create user directories
        console.info('Creating data directories for', handle, '(invited by', invite.createdBy, ')');
        await ensurePublicDirectoriesExist();
        const directories = getUserDirectories(handle);
        await checkForNewContent([directories], [CONTENT_TYPES.SETTINGS]);

        // Mark invite as used
        invite.status = 'accepted';
        invite.usedBy = handle;
        invite.usedAt = Date.now();
        await storage.setItem(inviteKey(invite.id), invite);

        return response.json({ handle });
    } catch (error) {
        console.error('Accept invitation failed:', error);
        return response.sendStatus(500);
    }
});
