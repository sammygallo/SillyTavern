import express from 'express';

import {
    PERMISSIONS,
    PERMISSION_CATEGORIES,
    getAllPermissionGroups,
    getPermissionGroupById,
    createPermissionGroup,
    updatePermissionGroup,
    deletePermissionGroup,
    generateGroupId,
    validateGroupInput,
    requirePermission,
    hasPermission,
    canAssignGroup,
    canEditGroup,
    countAllMembersOfGroup,
    countEnabledMembersOfGroup,
} from '../permissions.js';

export const router = express.Router();

/**
 * GET /api/permissions
 *
 * Returns the master permission vocabulary, grouped by category, so the
 * frontend can render the group editor without hard-coding the list.
 *
 * Requires login only (any authenticated user may read the vocabulary —
 * it's public metadata).
 */
router.get('/permissions', async (_request, response) => {
    return response.json({
        permissions: PERMISSIONS,
        categories: PERMISSION_CATEGORIES,
    });
});

/**
 * GET /api/permission-groups
 *
 * Lists every permission group. Any authenticated user can see the list
 * (groups are not secret — the UI needs to resolve group-id -> name in many
 * places). Sensitive state like member counts is only included for users
 * with `admin:users:view`.
 */
router.get('/permission-groups', async (request, response) => {
    if (!request.user) return response.sendStatus(403);

    try {
        const groups = await getAllPermissionGroups();
        const canSeeMembers = await hasPermission(request.user.profile, 'admin:users:view');

        if (!canSeeMembers) {
            return response.json(groups);
        }

        const withCounts = await Promise.all(groups.map(async (g) => {
            const memberCount = await countAllMembersOfGroup(g.id);
            const enabledMemberCount = await countEnabledMembersOfGroup(g.id);
            return { ...g, memberCount, enabledMemberCount };
        }));
        return response.json(withCounts);
    } catch (error) {
        console.error('List permission groups failed:', error);
        return response.sendStatus(500);
    }
});

/**
 * POST /api/permission-groups/create
 *
 * Creates a new custom permission group.
 *
 * Rules (beyond middleware):
 *   - The requested permission set must be a subset of the actor's own
 *     permissions (no privilege escalation via group authoring).
 *
 * Body: { name, description, permissions }
 * Returns: the created group.
 */
router.post('/permission-groups/create', requirePermission('admin:groups:manage'), async (request, response) => {
    try {
        const validation = validateGroupInput(request.body, 'create');
        if (!validation.ok) {
            return response.status(400).json({ error: validation.error });
        }
        const { name, description, permissions } = validation.value;

        // Privilege-escalation guard: the actor must hold every permission
        // they're granting. Synthesize a pseudo-group to reuse canAssignGroup.
        const pseudo = { permissions };
        // @ts-ignore — pseudo is intentionally minimal
        const ok = await canAssignGroup(request.user.profile, pseudo);
        if (!ok) {
            return response.status(403).json({
                error: 'Cannot create a group with permissions you don\'t hold yourself',
            });
        }

        const id = await generateGroupId(name);
        const group = await createPermissionGroup({
            id,
            name,
            description,
            permissions,
            createdByHandle: request.user.profile.handle,
        });
        return response.json(group);
    } catch (error) {
        console.error('Create permission group failed:', error);
        const status = /** @type {any} */ (error)?.status || 500;
        return response.status(status).json({ error: error.message || 'Internal error' });
    }
});

/**
 * POST /api/permission-groups/update
 *
 * Updates an existing permission group.
 *
 * Rules (beyond middleware):
 *   - systemOwner groups: name and description can be changed; permission
 *     set is locked to the full vocabulary.
 *   - The edit must not add permissions the actor does not hold (prevents
 *     self-escalation when the actor is a member of the edited group).
 *
 * Body: { id, name?, description?, permissions? }
 */
router.post('/permission-groups/update', requirePermission('admin:groups:manage'), async (request, response) => {
    try {
        const { id } = request.body || {};
        if (!id || typeof id !== 'string') {
            return response.status(400).json({ error: 'id is required' });
        }

        const group = await getPermissionGroupById(id);
        if (!group) {
            return response.status(404).json({ error: `Group '${id}' not found` });
        }

        const validation = validateGroupInput(request.body, 'update');
        if (!validation.ok) {
            return response.status(400).json({ error: validation.error });
        }
        const { name, description, permissions } = validation.value;

        // If the actor is editing a non-systemOwner group's permission set,
        // enforce the no-self-escalation rule.
        if (!group.systemOwner && Array.isArray(request.body.permissions)) {
            const check = await canEditGroup(request.user.profile, group, permissions);
            if (!check.ok) {
                return response.status(403).json({ error: check.reason });
            }
        }

        const patch = {};
        if (typeof request.body.name === 'string') patch.name = name;
        if (typeof request.body.description === 'string') patch.description = description;
        if (Array.isArray(request.body.permissions)) patch.permissions = permissions;

        const updated = await updatePermissionGroup({ id, patch });
        return response.json(updated);
    } catch (error) {
        console.error('Update permission group failed:', error);
        const status = /** @type {any} */ (error)?.status || 500;
        return response.status(status).json({ error: error.message || 'Internal error' });
    }
});

/**
 * POST /api/permission-groups/delete
 *
 * Deletes a permission group.
 *
 * Rules (beyond middleware):
 *   - Cannot delete systemOwner group.
 *   - Cannot delete any system group (Owner / Admin / Contributor / End User).
 *   - Cannot delete a group that still has members.
 */
router.post('/permission-groups/delete', requirePermission('admin:groups:manage'), async (request, response) => {
    try {
        const { id } = request.body || {};
        if (!id || typeof id !== 'string') {
            return response.status(400).json({ error: 'id is required' });
        }
        await deletePermissionGroup(id);
        return response.json({ id });
    } catch (error) {
        console.error('Delete permission group failed:', error);
        const status = /** @type {any} */ (error)?.status || 500;
        return response.status(status).json({ error: error.message || 'Internal error' });
    }
});
