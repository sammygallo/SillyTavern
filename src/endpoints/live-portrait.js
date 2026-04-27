/**
 * Live Portrait — generate animated character clips via Replicate's
 * wan-video/wan-2.2-i2v-fast model.
 *
 * GGBC's static-avatar replacement: instead of warping a single image at
 * render time, we generate a small set of MP4 clips per character at setup
 * time and play them on loop in chat. Idle clip when the AI isn't talking,
 * per-emotion clip when it is.
 *
 * Why server-side: the Replicate API key lives in the user's secrets store
 * and must never reach the browser. This module is the trusted middleman —
 * frontend posts a character name + emotion list, this route reads the secret,
 * uploads the avatar to Replicate Files (to get an HTTPS URL the model can
 * fetch), calls wan-2.2-i2v-fast once per emotion, saves the resulting MP4s
 * into the character data dir, and returns URLs the frontend can <video>.
 *
 * Replicate API contract (wan-video/wan-2.2-i2v-fast):
 *   POST https://api.replicate.com/v1/models/wan-video/wan-2.2-i2v-fast/predictions
 *     headers: { Authorization: "Bearer <key>", Content-Type: "application/json",
 *                Prefer: "wait=60" }
 *     body: { input: { image: "<https url>", prompt: "<emotion prompt>",
 *                      num_frames: 81, resolution: "480p", frames_per_second: 16 } }
 *     → { id, status: "starting"|"processing"|"succeeded"|"failed"|"canceled",
 *          output: null | string | string[] }
 *   GET https://api.replicate.com/v1/predictions/{id}
 *     → same shape; poll until status is "succeeded" or terminal
 *
 * Job tracking is in-memory: simple Map<jobId, JobState>. Restart wipes them;
 * the frontend re-issues if needed.
 */

import fs from 'node:fs';
import path from 'node:path';

import express from 'express';
import fetch from 'node-fetch';
import FormData from 'form-data';

import { readSecret, SECRET_KEYS } from './secrets.js';
import { resolveCharacterPath, getGlobalCharactersDir } from '../character-globals.js';

export const router = express.Router();

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const REPLICATE_WAN_URL = 'https://api.replicate.com/v1/models/wan-video/wan-2.2-i2v-fast/predictions';
const REPLICATE_POLL_BASE = 'https://api.replicate.com/v1/predictions';

/** Canonical emotion set — order matters for UI display. */
const SUPPORTED_EMOTIONS = ['idle', 'happy', 'sad', 'angry', 'surprised', 'neutral'];

/**
 * Per-emotion text prompts. The wan model infers the character's visual style
 * from the source image; the prompt describes the desired motion and expression.
 */
const EMOTION_PROMPTS = {
    idle: 'subtle breathing motion, calm neutral expression, gentle idle animation, slight head movement',
    happy: 'smiling warmly, happy joyful expression, eyes slightly squinting with joy, gentle head movement',
    sad: 'sad downcast expression, slightly drooping head, melancholy look, subtle movement',
    angry: 'angry expression, furrowed brows, intense gaze, slight jaw tension',
    surprised: 'surprised expression, wide eyes, eyebrows raised, slight backward head movement',
    neutral: 'neutral calm expression, relaxed face, minimal movement, subtle breathing',
};

const POLL_INTERVAL_MS = 3000;
const POLL_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes per clip

// ---------------------------------------------------------------------------
// In-memory job tracking
// ---------------------------------------------------------------------------

/**
 * @typedef {object} JobState
 * @property {'queued'|'running'|'completed'|'error'} status
 * @property {number} progress 0..1, fraction of clips finished
 * @property {Record<string, string>} clips emotion → public URL of saved MP4
 * @property {string|null} error
 * @property {number} startedAt epoch ms
 */

/** @type {Map<string, JobState>} */
const jobs = new Map();

setInterval(() => {
    const now = Date.now();
    for (const [id, state] of jobs.entries()) {
        if (state.status === 'completed' || state.status === 'error') {
            if (now - state.startedAt > 30 * 60 * 1000) jobs.delete(id);
        }
    }
}, 10 * 60 * 1000).unref();

// ---------------------------------------------------------------------------
// Replicate client
// ---------------------------------------------------------------------------

function extractOutput(prediction) {
    const output = prediction.output;
    if (!output) throw new Error('Replicate prediction succeeded but returned no output');
    return Array.isArray(output) ? output[0] : output;
}

/**
 * Upload a buffer to Replicate Files API as multipart/form-data.
 * The SDK uses FormData with a `content` field + empty `metadata` field.
 * Returns the HTTPS URL the wan model can fetch.
 *
 * @param {string} apiKey
 * @param {Buffer} buffer
 * @param {string} filename
 * @returns {Promise<string>}
 */
async function uploadToReplicateFiles(apiKey, buffer, filename) {
    const form = new FormData();
    form.append('content', buffer, { filename, contentType: 'application/octet-stream' });
    form.append('metadata', Buffer.from('{}'), { contentType: 'application/json' });

    const uploadRes = await fetch('https://api.replicate.com/v1/files', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${apiKey}`,
            ...form.getHeaders(),
        },
        body: form,
    });
    if (!uploadRes.ok) {
        const txt = await uploadRes.text().catch(() => '');
        throw new Error(`Replicate file upload failed (${uploadRes.status}): ${txt.slice(0, 200)}`);
    }
    const data = await uploadRes.json();
    const url = data?.urls?.get;
    if (!url) throw new Error('Replicate file upload returned no URL');
    return url;
}

/**
 * Submit a single wan-2.2-i2v-fast job and poll until done.
 * Returns the URL of the rendered MP4 (Replicate-hosted).
 *
 * @param {string} apiKey
 * @param {string} imageUrl HTTPS URL of the character portrait (from Replicate Files)
 * @param {string} emotionPrompt Motion/expression description
 * @returns {Promise<string>}
 */
async function generateOneClip(apiKey, imageUrl, emotionPrompt) {
    const submitRes = await fetch(REPLICATE_WAN_URL, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
            'Prefer': 'wait=60',
        },
        body: JSON.stringify({
            input: {
                image: imageUrl,
                prompt: emotionPrompt,
                num_frames: 81,
                resolution: '480p',
                frames_per_second: 16,
                go_fast: true,
            },
        }),
    });
    if (!submitRes.ok) {
        const txt = await submitRes.text().catch(() => '');
        throw new Error(`Replicate submit failed (${submitRes.status}): ${txt.slice(0, 200)}`);
    }
    let prediction = await submitRes.json();

    if (prediction.status === 'succeeded') return extractOutput(prediction);
    if (prediction.status === 'failed' || prediction.status === 'canceled') {
        throw new Error(`Replicate prediction ${prediction.status}: ${prediction.error ?? 'unknown'}`);
    }

    const predictionId = prediction.id;
    if (!predictionId) throw new Error('Replicate response missing prediction id');

    const startedAt = Date.now();
    while (Date.now() - startedAt < POLL_TIMEOUT_MS) {
        await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));
        const pollRes = await fetch(`${REPLICATE_POLL_BASE}/${predictionId}`, {
            headers: { 'Authorization': `Bearer ${apiKey}` },
        });
        if (!pollRes.ok) {
            const txt = await pollRes.text().catch(() => '');
            throw new Error(`Replicate poll failed (${pollRes.status}): ${txt.slice(0, 200)}`);
        }
        prediction = await pollRes.json();
        if (prediction.status === 'succeeded') return extractOutput(prediction);
        if (prediction.status === 'failed' || prediction.status === 'canceled') {
            throw new Error(`Replicate prediction ${prediction.status}: ${prediction.error ?? 'unknown'}`);
        }
    }
    throw new Error('Replicate prediction timed out after 5 minutes');
}

async function downloadTo(url, destPath) {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Download failed (${res.status}) for ${url}`);
    await fs.promises.mkdir(path.dirname(destPath), { recursive: true });
    const buf = Buffer.from(await res.arrayBuffer());
    await fs.promises.writeFile(destPath, buf);
}

// ---------------------------------------------------------------------------
// Job runner
// ---------------------------------------------------------------------------

async function runJob(jobId, request, characterName, emotions) {
    const state = jobs.get(jobId);
    if (!state) return;

    try {
        const apiKey = readSecret(request.user.directories, SECRET_KEYS.REPLICATE);
        if (!apiKey) {
            state.status = 'error';
            state.error = 'No Replicate API key configured. Add it in Settings → AI → Live Portrait.';
            return;
        }

        // Resolve the character's portrait. Avatars live in either the user's
        // personal characters dir or _global/characters/ (for shared characters);
        // resolveCharacterPath checks the global scope first when registered.
        // We try the canonical {name}.png first, then expression-folder fallbacks
        // in the same scope.
        const avatarFilename = `${characterName}.png`;
        const resolved = resolveCharacterPath(request.user.directories, avatarFilename);
        const baseDir = resolved.scope === 'global'
            ? getGlobalCharactersDir()
            : request.user.directories.characters;

        const charSubDir = path.join(baseDir, characterName);
        const candidatePaths = [
            path.join(baseDir, avatarFilename),
            path.join(baseDir, `default_${avatarFilename}`),
            path.join(charSubDir, 'neutral.png'),
            path.join(charSubDir, 'admiration.png'),
            path.join(charSubDir, 'joy.png'),
        ];

        let avatarBuffer = null;
        for (const imgPath of candidatePaths) {
            try {
                avatarBuffer = await fs.promises.readFile(imgPath);
                break;
            } catch {
                // try next candidate
            }
        }
        if (!avatarBuffer) {
            state.status = 'error';
            state.error = `Avatar image not found for character "${characterName}". Make sure the character has a portrait set.`;
            return;
        }

        state.status = 'running';

        // Upload avatar once to Replicate Files; reuse the HTTPS URL for all clips.
        const avatarUrl = await uploadToReplicateFiles(
            apiKey, avatarBuffer, avatarFilename,
        );

        const total = emotions.length;
        let done = 0;
        const charDir = path.join(baseDir, characterName, 'live');
        await fs.promises.mkdir(charDir, { recursive: true });

        for (const emotion of emotions) {
            if (!SUPPORTED_EMOTIONS.includes(emotion)) {
                throw new Error(`Unsupported emotion: ${emotion}`);
            }
            const prompt = EMOTION_PROMPTS[emotion];
            const replicateOutputUrl = await generateOneClip(apiKey, avatarUrl, prompt);
            const localPath = path.join(charDir, `${emotion}.mp4`);
            await downloadTo(replicateOutputUrl, localPath);

            state.clips[emotion] = `/characters/${encodeURIComponent(characterName)}/live/${emotion}.mp4`;
            done += 1;
            state.progress = done / total;
        }

        state.status = 'completed';
        state.progress = 1;
    } catch (err) {
        state.status = 'error';
        state.error = err instanceof Error ? err.message : String(err);
    }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

router.post('/generate', async (request, response) => {
    try {
        const { characterName, emotions } = request.body ?? {};
        if (typeof characterName !== 'string' || characterName.length === 0) {
            return response.status(400).json({ error: 'characterName required' });
        }
        if (!Array.isArray(emotions) || emotions.length === 0) {
            return response.status(400).json({ error: 'emotions[] required' });
        }
        const invalid = emotions.filter(e => !SUPPORTED_EMOTIONS.includes(e));
        if (invalid.length > 0) {
            return response.status(400).json({
                error: `Unsupported emotions: ${invalid.join(', ')}. Supported: ${SUPPORTED_EMOTIONS.join(', ')}`,
            });
        }

        const jobId = `lp_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
        jobs.set(jobId, {
            status: 'queued',
            progress: 0,
            clips: {},
            error: null,
            startedAt: Date.now(),
        });

        runJob(jobId, request, characterName, emotions).catch(() => {});

        return response.json({ jobId, status: 'queued' });
    } catch (err) {
        return response.status(500).json({
            error: err instanceof Error ? err.message : 'Generation failed',
        });
    }
});

router.get('/status/:jobId', (request, response) => {
    const { jobId } = request.params;
    const state = jobs.get(jobId);
    if (!state) return response.status(404).json({ error: 'Unknown job id' });
    return response.json({
        status: state.status,
        progress: state.progress,
        clips: state.clips,
        error: state.error,
    });
});

/**
 * Discover any already-generated clips for a character. Lets clients
 * auto-populate their local clip-URL store on character load — without
 * this, only the device that ran generation knows the clips exist
 * (the URLs were saved to localStorage there).
 */
router.get('/list/:characterName', async (request, response) => {
    try {
        const { characterName } = request.params;
        if (!characterName) {
            return response.status(400).json({ error: 'characterName required' });
        }

        const avatarFilename = `${characterName}.png`;
        const resolved = resolveCharacterPath(request.user.directories, avatarFilename);
        const baseDir = resolved.scope === 'global'
            ? getGlobalCharactersDir()
            : request.user.directories.characters;

        const liveDir = path.join(baseDir, characterName, 'live');
        const clips = {};
        try {
            const files = await fs.promises.readdir(liveDir);
            for (const file of files) {
                if (!file.endsWith('.mp4')) continue;
                const emotion = file.slice(0, -4);
                if (!SUPPORTED_EMOTIONS.includes(emotion)) continue;
                clips[emotion] = `/characters/${encodeURIComponent(characterName)}/live/${file}`;
            }
        } catch {
            // No live/ dir yet — return empty.
        }

        return response.json({ clips });
    } catch (err) {
        return response.status(500).json({
            error: err instanceof Error ? err.message : 'List failed',
        });
    }
});

router.get('/emotions', (_request, response) => {
    return response.json({ emotions: SUPPORTED_EMOTIONS });
});
