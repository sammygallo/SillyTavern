import { promises as fsPromises } from 'node:fs';

import storage from 'node-persist';
import express from 'express';
import lodash from 'lodash';
import { checkForNewContent, CONTENT_TYPES } from './content-manager.js';
import {
    KEY_PREFIX,
    toKey,
    getUserAvatar,
    getAllUserHandles,
    getPasswordSalt,
    getPasswordHash,
    getUserDirectories,
    ensurePublicDirectoriesExist,
} from '../users.js';
import { DEFAULT_USER } from '../constants.js';
import {
    requirePermission,
    getPermissionGroupById,
    getUserPermissions,
    canAssignGroup,
    assertSystemOwnerInvariant,
    deriveLegacyShims,
    legacyRoleToGroupId,
    OWNER_GROUP_ID,
    END_USER_GROUP_ID,
} from '../permissions.js';

export const router = express.Router();

router.post('/get', requirePermission('admin:users:view'), async (_request, response) => {
    try {
        /** @type {import('../users.js').User[]} */
        const users = await storage.values(x => x.key.startsWith(KEY_PREFIX));

        const viewModelPromises = users.map(async (user) => {
            const avatar = await getUserAvatar(user.handle);
            const permissions = await getUserPermissions(user);
            return {
                handle: user.handle,
                name: user.name,
                avatar,
                groupId: user.groupId ?? null,
                permissions,
                // Legacy shims — still populated for external tooling
                admin: user.admin,
                role: user.role,
                enabled: user.enabled,
                created: user.created,
                password: !!user.password,
            };
        });

        const viewModels = await Promise.all(viewModelPromises);
        viewModels.sort((x, y) => (x.created ?? 0) - (y.created ?? 0));
        return response.json(viewModels);
    } catch (error) {
        console.error('User list failed:', error);
        return response.sendStatus(500);
    }
});

router.post('/disable', requirePermission('admin:users:manage'), async (request, response) => {
    try {
        if (!request.body.handle) {
            console.warn('Disable user failed: Missing required fields');
            return response.status(400).json({ error: 'Missing required fields' });
        }

        if (request.body.handle === request.user.profile.handle) {
            console.warn('Disable user failed: Cannot disable yourself');
            return response.status(400).json({ error: 'Cannot disable yourself' });
        }

        /** @type {import('../users.js').User} */
        const user = await storage.getItem(toKey(request.body.handle));

        if (!user) {
            console.error('Disable user failed: User not found');
            return response.status(404).json({ error: 'User not found' });
        }

        // systemOwner-anchor invariant: cannot disable the last enabled owner.
        if (user.groupId === OWNER_GROUP_ID) {
            try {
                await assertSystemOwnerInvariant({
                    operation: 'disable-user',
                    targetHandle: user.handle,
                });
            } catch (err) {
                return response.status(/** @type {any} */ (err).status || 409)
                    .json({ error: err.message });
            }
        }

        user.enabled = false;
        await storage.setItem(toKey(request.body.handle), user);
        return response.sendStatus(204);
    } catch (error) {
        console.error('User disable failed:', error);
        return response.sendStatus(500);
    }
});

router.post('/enable', requirePermission('admin:users:manage'), async (request, response) => {
    try {
        if (!request.body.handle) {
            console.warn('Enable user failed: Missing required fields');
            return response.status(400).json({ error: 'Missing required fields' });
        }

        /** @type {import('../users.js').User} */
        const user = await storage.getItem(toKey(request.body.handle));

        if (!user) {
            console.error('Enable user failed: User not found');
            return response.status(404).json({ error: 'User not found' });
        }

        user.enabled = true;
        await storage.setItem(toKey(request.body.handle), user);
        return response.sendStatus(204);
    } catch (error) {
        console.error('User enable failed:', error);
        return response.sendStatus(500);
    }
});

/**
 * @deprecated Use /set-group instead. Returns 410 Gone.
 */
router.post('/promote', requirePermission('admin:users:manage'), async (_request, response) => {
    return response.status(410).json({
        error: 'The /promote endpoint is deprecated. Use /api/users/set-group with a groupId instead.',
    });
});

/**
 * @deprecated Use /set-group instead. Returns 410 Gone.
 */
router.post('/demote', requirePermission('admin:users:manage'), async (_request, response) => {
    return response.status(410).json({
        error: 'The /demote endpoint is deprecated. Use /api/users/set-group with a groupId instead.',
    });
});

router.post('/create', requirePermission('admin:users:manage'), async (request, response) => {
    try {
        if (!request.body.handle || !request.body.name) {
            console.warn('Create user failed: Missing required fields');
            return response.status(400).json({ error: 'Missing required fields' });
        }

        const handles = await getAllUserHandles();
        const handle = lodash.kebabCase(String(request.body.handle).toLowerCase().trim());

        if (!handle) {
            console.warn('Create user failed: Invalid handle');
            return response.status(400).json({ error: 'Invalid handle' });
        }

        if (handles.some(x => x === handle)) {
            console.warn('Create user failed: User with that handle already exists');
            return response.status(409).json({ error: 'User already exists' });
        }

        const salt = getPasswordSalt();
        const password = request.body.password ? getPasswordHash(request.body.password, salt) : '';

        // Determine groupId: prefer explicit `groupId` from body, fall back to
        // the legacy `role`/`admin` shape for backward compat with old clients
        // (seed-owner.sh in particular).
        let targetGroupId;
        if (typeof request.body.groupId === 'string' && request.body.groupId) {
            targetGroupId = request.body.groupId;
        } else if (request.body.role || typeof request.body.admin === 'boolean') {
            console.warn(
                '[Permissions] Deprecated: /users/create body used { role, admin } shape — '
                + 'update caller to send { groupId } instead.',
            );
            targetGroupId = legacyRoleToGroupId(request.body.role, request.body.admin);
        } else {
            targetGroupId = END_USER_GROUP_ID;
        }

        const targetGroup = await getPermissionGroupById(targetGroupId);
        if (!targetGroup) {
            return response.status(400).json({ error: `Unknown group: ${targetGroupId}` });
        }

        // Privilege-escalation guard: the actor must be able to assign this group.
        const canAssign = await canAssignGroup(request.user.profile, targetGroup);
        if (!canAssign) {
            return response.status(403).json({
                error: `Cannot assign group '${targetGroupId}' — it contains permissions you don't hold`,
            });
        }

        const shims = deriveLegacyShims(targetGroup.permissions);

        const newUser = {
            handle: handle,
            name: request.body.name || 'Anonymous',
            created: Date.now(),
            password: password,
            salt: salt,
            groupId: targetGroupId,
            admin: shims.admin,
            role: shims.role,
            enabled: true,
        };

        await storage.setItem(toKey(handle), newUser);

        // Create user directories
        console.info('Creating data directories for', newUser.handle);
        await ensurePublicDirectoriesExist();
        const directories = getUserDirectories(newUser.handle);
        await checkForNewContent([directories], [CONTENT_TYPES.SETTINGS]);
        return response.json({ handle: newUser.handle });
    } catch (error) {
        console.error('User create failed:', error);
        return response.sendStatus(500);
    }
});

router.post('/delete', requirePermission('admin:users:manage'), async (request, response) => {
    try {
        if (!request.body.handle) {
            console.warn('Delete user failed: Missing required fields');
            return response.status(400).json({ error: 'Missing required fields' });
        }

        if (request.body.handle === request.user.profile.handle) {
            console.warn('Delete user failed: Cannot delete yourself');
            return response.status(400).json({ error: 'Cannot delete yourself' });
        }

        if (request.body.handle === DEFAULT_USER.handle) {
            console.warn('Delete user failed: Cannot delete default user');
            return response.status(400).json({ error: 'Sorry, but the default user cannot be deleted. It is required as a fallback.' });
        }

        /** @type {import('../users.js').User} */
        const targetUser = await storage.getItem(toKey(request.body.handle));
        if (!targetUser) {
            return response.status(404).json({ error: 'User not found' });
        }

        // systemOwner-anchor invariant: cannot delete the last enabled owner.
        if (targetUser.groupId === OWNER_GROUP_ID) {
            try {
                await assertSystemOwnerInvariant({
                    operation: 'delete-user',
                    targetHandle: targetUser.handle,
                });
            } catch (err) {
                return response.status(/** @type {any} */ (err).status || 409)
                    .json({ error: err.message });
            }
        }

        // Privilege guard: you can only delete someone whose group you could
        // assign yourself (i.e. whose permissions are a subset of yours).
        if (targetUser.groupId) {
            const targetGroup = await getPermissionGroupById(targetUser.groupId);
            if (targetGroup) {
                const allowed = await canAssignGroup(request.user.profile, targetGroup);
                if (!allowed) {
                    return response.status(403).json({
                        error: 'Cannot delete this user — they hold permissions you do not',
                    });
                }
            }
        }

        await storage.removeItem(toKey(request.body.handle));

        if (request.body.purge) {
            const directories = getUserDirectories(request.body.handle);
            console.info('Deleting data directories for', request.body.handle);
            await fsPromises.rm(directories.root, { recursive: true, force: true });
        }

        return response.sendStatus(204);
    } catch (error) {
        console.error('User delete failed:', error);
        return response.sendStatus(500);
    }
});

router.post('/slugify', requirePermission('admin:users:manage'), async (request, response) => {
    try {
        if (!request.body.text) {
            console.warn('Slugify failed: Missing required fields');
            return response.status(400).json({ error: 'Missing required fields' });
        }

        const text = lodash.kebabCase(String(request.body.text).toLowerCase().trim());

        return response.send(text);
    } catch (error) {
        console.error('Slugify failed:', error);
        return response.sendStatus(500);
    }
});

/**
 * POST /api/users/set-group
 *
 * Assigns a user to a permission group. Replaces the legacy /set-role endpoint.
 *
 * Rules:
 *   - Actor must hold `admin:users:set_group`.
 *   - Actor cannot change their own group (prevents accidental lockout).
 *   - Actor must hold every permission in the target group (no privilege
 *     escalation via group assignment).
 *   - systemOwner-anchor invariant: cannot move the last enabled owner out
 *     of the owner group.
 */
router.post('/set-group', requirePermission('admin:users:set_group'), async (request, response) => {
    try {
        if (!request.body.handle || !request.body.groupId) {
            return response.status(400).json({ error: 'Missing required fields' });
        }

        if (request.body.handle === request.user.profile.handle) {
            return response.status(400).json({ error: 'Cannot change your own group' });
        }

        /** @type {import('../users.js').User} */
        const user = await storage.getItem(toKey(request.body.handle));
        if (!user) {
            return response.status(404).json({ error: 'User not found' });
        }

        const targetGroup = await getPermissionGroupById(request.body.groupId);
        if (!targetGroup) {
            return response.status(400).json({ error: `Unknown group: ${request.body.groupId}` });
        }

        // Privilege guard for the NEW group.
        const canAssignNew = await canAssignGroup(request.user.profile, targetGroup);
        if (!canAssignNew) {
            return response.status(403).json({
                error: `Cannot assign group '${targetGroup.id}' — it contains permissions you don't hold`,
            });
        }

        // Privilege guard for the CURRENT group — you must also be able to
        // manage a user at their current privilege level (otherwise an admin
        // could "demote" an owner, which is the old lockout path).
        if (user.groupId) {
            const currentGroup = await getPermissionGroupById(user.groupId);
            if (currentGroup) {
                const canManageCurrent = await canAssignGroup(request.user.profile, currentGroup);
                if (!canManageCurrent) {
                    return response.status(403).json({
                        error: 'Cannot change this user\'s group — they hold permissions you don\'t',
                    });
                }
            }
        }

        // systemOwner-anchor: if the user is being moved OUT of the owner group,
        // there must still be at least one other enabled owner.
        if (user.groupId === OWNER_GROUP_ID && targetGroup.id !== OWNER_GROUP_ID) {
            try {
                await assertSystemOwnerInvariant({
                    operation: 'move-user-out',
                    targetHandle: user.handle,
                });
            } catch (err) {
                return response.status(/** @type {any} */ (err).status || 409)
                    .json({ error: err.message });
            }
        }

        user.groupId = targetGroup.id;
        const shims = deriveLegacyShims(targetGroup.permissions);
        user.admin = shims.admin;
        user.role = shims.role;
        await storage.setItem(toKey(user.handle), user);

        return response.sendStatus(204);
    } catch (error) {
        console.error('Set group failed:', error);
        return response.sendStatus(500);
    }
});

/**
 * POST /api/users/set-role
 *
 * Legacy shim. Maps an old-shape `{ handle, role }` request to the new
 * set-group flow. Kept so that any existing tooling that calls /set-role
 * keeps working during the transition window.
 *
 * @deprecated Clients should call /set-group with a groupId instead.
 */
router.post('/set-role', requirePermission('admin:users:set_group'), async (request, response) => {
    try {
        if (!request.body.handle || !request.body.role) {
            return response.status(400).json({ error: 'Missing required fields' });
        }
        console.warn(
            `[Permissions] Deprecated: /users/set-role called by '${request.user.profile.handle}' — `
            + 'update caller to use /users/set-group with a groupId.',
        );

        const targetGroupId = legacyRoleToGroupId(request.body.role, undefined);

        // Re-dispatch through the set-group logic by calling the same code path.
        // We do this inline rather than delegating to keep the path clean.
        if (request.body.handle === request.user.profile.handle) {
            return response.status(400).json({ error: 'Cannot change your own role' });
        }

        /** @type {import('../users.js').User} */
        const user = await storage.getItem(toKey(request.body.handle));
        if (!user) {
            return response.status(404).json({ error: 'User not found' });
        }

        const targetGroup = await getPermissionGroupById(targetGroupId);
        if (!targetGroup) {
            return response.status(400).json({ error: `Unknown group: ${targetGroupId}` });
        }

        const canAssignNew = await canAssignGroup(request.user.profile, targetGroup);
        if (!canAssignNew) {
            return response.status(403).json({
                error: `Cannot assign role '${request.body.role}'`,
            });
        }

        if (user.groupId) {
            const currentGroup = await getPermissionGroupById(user.groupId);
            if (currentGroup) {
                const canManageCurrent = await canAssignGroup(request.user.profile, currentGroup);
                if (!canManageCurrent) {
                    return response.status(403).json({
                        error: 'Cannot change this user\'s role',
                    });
                }
            }
        }

        if (user.groupId === OWNER_GROUP_ID && targetGroup.id !== OWNER_GROUP_ID) {
            try {
                await assertSystemOwnerInvariant({
                    operation: 'move-user-out',
                    targetHandle: user.handle,
                });
            } catch (err) {
                return response.status(/** @type {any} */ (err).status || 409)
                    .json({ error: err.message });
            }
        }

        user.groupId = targetGroup.id;
        const shims = deriveLegacyShims(targetGroup.permissions);
        user.admin = shims.admin;
        user.role = shims.role;
        await storage.setItem(toKey(user.handle), user);

        return response.sendStatus(204);
    } catch (error) {
        console.error('Set role failed:', error);
        return response.sendStatus(500);
    }
});
