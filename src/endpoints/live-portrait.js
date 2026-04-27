/**
 * Live Portrait — generate animated character clips via Replicate's
 * fofr/live-portrait model.
 *
 * GGBC's static-avatar replacement: instead of warping a single image at
 * render time (the previous mesh-warp approach), we generate a small set of
 * MP4 clips per character at setup time and play them on loop in chat.
 * Idle clip when the AI isn't talking, per-emotion clip when it is.
 *
 * Why server-side: the Replicate API key (api_key_replicate) lives in the
 * user's secrets store and must never reach the browser. This module is the
 * trusted middleman — frontend posts an avatar + an emotion list, this
 * route reads the secret, calls Replicate, saves the resulting MP4s into the
 * character's data directory, and returns URLs the frontend can <video>.
 *
 * Replicate API contract (fofr/live-portrait model):
 *   POST https://api.replicate.com/v1/models/fofr/live-portrait/predictions
 *     headers: { Authorization: "Bearer <key>", Content-Type: "application/json",
 *                Prefer: "wait=30" }
 *     body: { input: { source_image: "<url>", driving_video: "<url>" } }
 *     → { id, status: "starting"|"processing"|"succeeded"|"failed"|"canceled",
 *          output: null | string | string[] }
 *   GET https://api.replicate.com/v1/predictions/{id}
 *     → same shape; poll until status is "succeeded" or terminal
 *
 * Job tracking is in-memory: simple Map<jobId, JobState>. There's no Redis or
 * durable queue in this codebase, and jobs only need to survive a single
 * polling cycle from the frontend (~30–60s). Restart wipes them; the
 * frontend re-issues if needed.
 */

import fs from 'node:fs';
import path from 'node:path';

import express from 'express';
import fetch from 'node-fetch';

import { readSecret, SECRET_KEYS } from './secrets.js';

export const router = express.Router();

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const REPLICATE_PREDICT_URL = 'https://api.replicate.com/v1/models/fofr/live-portrait/predictions';
const REPLICATE_POLL_BASE = 'https://api.replicate.com/v1/predictions';

/**
 * Per-emotion driving videos that Replicate transfers onto the user's avatar.
 * These need to be publicly accessible URLs that Replicate can fetch from.
 * For dev we point at GGBC-hosted clips on a public CDN; for production swap
 * in your own URLs (see README — emotion-driver-videos section).
 *
 * Each clip should be ~5–10s, 24fps, neutral-faced subject performing the
 * targeted emotion (slight smile for "happy", frown for "sad", etc.).
 *
 * TODO(GGBC-team): replace the placeholder URLs below with real clips
 * once we've recorded the driving set.
 */
const DRIVING_VIDEOS = {
    idle: 'https://example.invalid/live-portrait-drivers/idle.mp4',
    happy: 'https://example.invalid/live-portrait-drivers/happy.mp4',
    sad: 'https://example.invalid/live-portrait-drivers/sad.mp4',
    angry: 'https://example.invalid/live-portrait-drivers/angry.mp4',
    surprised: 'https://example.invalid/live-portrait-drivers/surprised.mp4',
    neutral: 'https://example.invalid/live-portrait-drivers/neutral.mp4',
};

const SUPPORTED_EMOTIONS = Object.keys(DRIVING_VIDEOS);

const POLL_INTERVAL_MS = 2000;
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

/**
 * Garbage-collect old completed/error jobs every 10 minutes. In-memory only;
 * no recovery on restart.
 */
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

/**
 * Extract the output URL from a completed Replicate prediction.
 * Replicate models can return a single string or an array of strings.
 *
 * @param {object} prediction
 * @returns {string}
 */
function extractOutput(prediction) {
    const output = prediction.output;
    if (!output) throw new Error('Replicate prediction succeeded but returned no output');
    return Array.isArray(output) ? output[0] : output;
}

/**
 * Submit a single Live Portrait job to Replicate and poll until it's done.
 * Returns the URL of the rendered MP4 (Replicate-hosted).
 *
 * Uses `Prefer: wait=30` so that short predictions resolve in the initial
 * response without a separate poll round-trip.
 *
 * @param {string} apiKey
 * @param {string} sourceImageUrl URL Replicate can fetch (the character avatar)
 * @param {string} drivingVideoUrl URL of the driving emotion clip
 * @returns {Promise<string>} URL of the rendered MP4
 */
async function generateOneClip(apiKey, sourceImageUrl, drivingVideoUrl) {
    const submitRes = await fetch(REPLICATE_PREDICT_URL, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
            'Prefer': 'wait=30',
        },
        body: JSON.stringify({
            input: {
                source_image: sourceImageUrl,
                driving_video: drivingVideoUrl,
            },
        }),
    });
    if (!submitRes.ok) {
        const txt = await submitRes.text().catch(() => '');
        throw new Error(`Replicate submit failed (${submitRes.status}): ${txt.slice(0, 200)}`);
    }
    let prediction = await submitRes.json();

    // Prefer: wait=30 may return a fully completed prediction immediately.
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
        // starting / processing — keep polling
    }
    throw new Error('Replicate prediction timed out after 5 minutes');
}

/**
 * Download a remote video URL into the given local file path.
 *
 * @param {string} url
 * @param {string} destPath
 */
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

/**
 * Run a multi-emotion generation job in the background. Updates the in-memory
 * jobs map as each clip finishes.
 */
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

        // The browser will already have access to /characters/<name> via
        // the existing static route, but Replicate needs an absolute URL. We
        // build one from the request's host/protocol.
        const proto = request.protocol;
        const host = request.get('host');
        const sourceImageUrl = `${proto}://${host}/characters/${encodeURIComponent(characterName)}.png`;

        state.status = 'running';

        const total = emotions.length;
        let done = 0;
        const charDir = path.join(request.user.directories.characters, characterName, 'live');
        await fs.promises.mkdir(charDir, { recursive: true });

        for (const emotion of emotions) {
            if (!SUPPORTED_EMOTIONS.includes(emotion)) {
                throw new Error(`Unsupported emotion: ${emotion}`);
            }
            const drivingUrl = DRIVING_VIDEOS[emotion];
            const replicateOutputUrl = await generateOneClip(apiKey, sourceImageUrl, drivingUrl);
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

        // Fire-and-forget. The frontend polls /status/:jobId.
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

router.get('/emotions', (_request, response) => {
    return response.json({ emotions: SUPPORTED_EMOTIONS });
});
