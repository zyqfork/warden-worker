/**
 * Send upload/download fast-path for Warden Worker (JS)
 *
 * This module implements:
 * - Send file upload (zero-copy streaming to R2/KV)
 * - Send file download (zero-copy streaming from R2/KV)
 *
 * Route matching is handled by `src/entry.js`.
 */

import { getJwtSecret, verifyHs256Jwt } from "./jwt.js";
import {
  getStorageBackend,
  invalidTokenResponse,
  jsonError,
  nowString,
  putRequestToStorage,
  streamDownloadFromStorage,
} from "./streaming-common.js";

/**
 * Handle Send file upload: PUT /api/sends/{sendId}/file/{fileId}/azure-upload?token=...
 */
export async function handleSendUpload(request, env, sendId, fileId, token) {
  const backend = getStorageBackend(env);
  if (!backend) return jsonError("File storage is not enabled", 400);

  const db = env.vault1;
  if (!db) return jsonError("Database not available", 500);

  let claims;
  try {
    claims = await verifyHs256Jwt(token, getJwtSecret(env));
  } catch (err) {
    return invalidTokenResponse("sends.upload", err);
  }

  if (claims.send_id !== sendId || claims.file_id !== fileId) {
    return invalidTokenResponse(
      "sends.upload",
      `claims mismatch: expected send_id=${sendId}, file_id=${fileId}; got send_id=${claims.send_id}, file_id=${claims.file_id}`
    );
  }

  const userId = claims.sub;

  const pending = await db
    .prepare("SELECT * FROM sends_pending WHERE id = ?1 AND user_id = ?2")
    .bind(sendId, userId)
    .first();

  if (!pending) return jsonError("Pending send not found or already uploaded", 404);

  let pendingData;
  try {
    pendingData = JSON.parse(pending.data);
  } catch {
    return jsonError("Invalid pending send data", 500);
  }
  if (pendingData.id !== fileId) return jsonError("File ID mismatch", 400);

  const declaredSize = pendingData.size;
  if (typeof declaredSize !== "number" || declaredSize <= 0) {
    return jsonError("Invalid declared file size in pending send", 400);
  }

  const storageKey = `sends/${sendId}/${fileId}`;
  try {
    await putRequestToStorage({
      env,
      request,
      storageKey,
      declaredSize,
    });
  } catch (err) {
    return jsonError(err.message, err.status || 500);
  }

  const fileData = JSON.stringify(pendingData);

  const now = nowString();
  await db.batch([
    db.prepare("DELETE FROM sends_pending WHERE id = ?1").bind(sendId),
    db.prepare(
      "INSERT INTO sends (id, user_id, name, notes, type, data, akey, password_hash, password_salt, password_iter, max_access_count, access_count, created_at, updated_at, expiration_date, deletion_date, disabled, hide_email) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)"
    ).bind(
      sendId,
      pending.user_id,
      pending.name,
      pending.notes,
      pending.type,
      fileData,
      pending.akey,
      pending.password_hash,
      pending.password_salt,
      pending.password_iter,
      pending.max_access_count,
      pending.access_count,
      pending.created_at,
      now,
      pending.expiration_date,
      pending.deletion_date,
      pending.disabled,
      pending.hide_email
    ),
    db.prepare("UPDATE users SET updated_at = ?1 WHERE id = ?2").bind(now, userId),
  ]);

  // Publish notification via NotifyDo
  if (env.NOTIFY_DO) {
    try {
      const id = env.NOTIFY_DO.idFromName("global");
      const stub = env.NOTIFY_DO.get(id);
      const response = await stub.fetch("https://notify.internal/publish-js-send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          userId,
          updateType: 12, // SyncSendCreate
          sendId,
          payloadUserId: userId,
          revisionDate: now,
        }),
      });
      if (!response.ok) {
        console.error("NotifyDo publish failed for send upload finalize", response.status);
      }
    } catch (err) {
      console.error("NotifyDo publish threw during send upload finalize", err);
    }
  }

  return new Response(null, { status: 201 });
}

/**
 * Handle Send file download: GET /api/sends/{sendId}/{fileId}?t=...
 */
export async function handleSendDownload(request, env, sendId, fileId, token) {
  const backend = getStorageBackend(env);
  if (!backend) return jsonError("File storage is not enabled", 400);

  const db = env.vault1;
  if (!db) return jsonError("Database not available", 500);

  let claims;
  try {
    claims = await verifyHs256Jwt(token, getJwtSecret(env));
  } catch (err) {
    return invalidTokenResponse("sends.download", err);
  }

  if (claims.send_id !== sendId || claims.file_id !== fileId) {
    return invalidTokenResponse(
      "sends.download",
      `claims mismatch: expected send_id=${sendId}, file_id=${fileId}; got send_id=${claims.send_id}, file_id=${claims.file_id}`
    );
  }

  const send = await db
    .prepare("SELECT * FROM sends WHERE id = ?1")
    .bind(sendId)
    .first();

  if (!send) return jsonError("Send not found", 404);

  const storageKey = `sends/${sendId}/${fileId}`;
  let fileSize = null;
  try {
    const data = JSON.parse(send.data);
    if (typeof data.size === "number" && data.size >= 0) {
      fileSize = data.size;
    }
  } catch {
    // Ignore malformed metadata and stream without a fallback size.
  }

  const response = await streamDownloadFromStorage({
    env,
    storageKey,
    fallbackSize: fileSize,
  });
  if (!response) return jsonError("File not found in storage", 404);
  return response;
}
