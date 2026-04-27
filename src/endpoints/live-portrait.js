/**
 * Live Portrait — generate animated character clips via Sieve's API.
 *
 * GGBC's static-avatar replacement: instead of warping a single image at
 * render time (the previous mesh-warp approach), we generate a small set of
 * MP4 clips per character at setup time and play them on loop in chat.
 * Idle clip when the AI isn't talking, per-emotion clip when it is.
 *
 * Why server-side: the Sieve API key (api_key_sieve) lives in the user's
 * secrets store and must never reach the browser. This module is the
 * trusted middleman — frontend posts an avatar + an emotion list, this
 * route reads the secret, calls Sieve, saves the resulting MP4s into the
 * character's data directory, and returns URLs the frontend can <video>.
 *
 * Sieve API contract assumptions (TODO: verify against current docs at
 * https://docs.sievedata.com when actually wiring up a real key — these
 * values are placeholders that match Sieve's documented shape ca. 2024):
 *   POST https://mango.sievedata.com/v2/push
 *     headers: { Authorization: "Bearer <key>", Content-Type: "application/json" }
 *     body: { function: "sieve/live-portrait", inputs: {...} }
 *     → { id, status: "queued" }
 *   GET https://mango.sievedata.com/v2/jobs/{id}
 *     → { status: "queued"|"processing"|"finished"|"error", outputs: [{url}], error? }
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

const SIEVE_PUSH_URL = 'https://mango.sievedata.com/v2/push';
const SIEVE_JOB_URL = 'https://mango.sievedata.com/v2/jobs';
const SIEVE_FUNCTION = 'sieve/live-portrait';

/**
 * Per-emotion driving videos that Sieve transfers onto the user's avatar.
 * These need to be hosted somewhere Sieve can fetch from. For dev we point
 * at GGBC-hosted clips on a public CDN; for production swap in your own
 * URLs (see README — emotion-driver-videos section).
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
// Sieve client
// ---------------------------------------------------------------------------

/**
 * Submit a single Live Portrait job to Sieve and poll until it's done.
 * Returns the URL of the rendered MP4 (Sieve-hosted).
 *
 * @param {string} apiKey
 * @param {string} sourceImageUrl URL Sieve can fetch (the character avatar)
 * @param {string} drivingVideoUrl URL of the driving emotion clip
 * @returns {Promise<string>} URL of the rendered MP4
 */
async function generateOneClip(apiKey, sourceImageUrl, drivingVideoUrl) {
    const pushRes = await fetch(SIEVE_PUSH_URL, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            function: SIEVE_FUNCTION,
            inputs: {
                source_image: sourceImageUrl,
                driving_video: drivingVideoUrl,
            },
        }),
    });
    if (!pushRes.ok) {
        const txt = await pushRes.text().catch(() => '');
        throw new Error(`Sieve push failed (${pushRes.status}): ${txt.slice(0, 200)}`);
    }
    const pushData = await pushRes.json();
    const jobId = pushData?.id;
    if (!jobId) throw new Error('Sieve push response missing job id');

    const startedAt = Date.now();
    while (Date.now() - startedAt < POLL_TIMEOUT_MS) {
        await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));
        const jobRes = await fetch(`${SIEVE_JOB_URL}/${jobId}`, {
            headers: { 'Authorization': `Bearer ${apiKey}` },
        });
        if (!jobRes.ok) {
            const txt = await jobRes.text().catch(() => '');
            throw new Error(`Sieve poll failed (${jobRes.status}): ${txt.slice(0, 200)}`);
        }
        const jobData = await jobRes.json();
        if (jobData?.status === 'finished') {
            const url = jobData?.outputs?.[0]?.url;
            if (!url) throw new Error('Sieve job finished but no output URL');
            return url;
        }
        if (jobData?.status === 'error') {
            throw new Error(`Sieve job errored: ${jobData?.error ?? 'unknown'}`);
        }
        // queued / processing — keep polling
    }
    throw new Error('Sieve job timed out after 5 minutes');
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
        const apiKey = readSecret(request.user.directories, SECRET_KEYS.SIEVE);
        if (!apiKey) {
            state.status = 'error';
            state.error = 'No Sieve API key configured. Add it in Settings → API.';
            return;
        }

        // The browser will already have access to /characters/<name> via
        // the existing static route, but Sieve needs an absolute URL. We
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
            const sieveOutputUrl = await generateOneClip(apiKey, sourceImageUrl, drivingUrl);
            const localPath = path.join(charDir, `${emotion}.mp4`);
            await downloadTo(sieveOutputUrl, localPath);

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
