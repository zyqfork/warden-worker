/**
 * Attachment upload/download fast-path for Warden Worker (JS)
 *
 * This module implements:
 * - Attachment upload logic (zero-copy streaming to R2/KV)
 * - Attachment download logic (zero-copy streaming from R2/KV)
 *
 * Route matching and URL parsing should be handled by `src/entry.js`.
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

// Handle azure-upload with zero-copy streaming (R2) or arrayBuffer (KV)
export async function handleAzureUpload(request, env, cipherId, attachmentId, token) {
  // Check storage backend
  const backend = getStorageBackend(env);
  if (!backend) {
    return jsonError("Attachments are not enabled", 400);
  }

  // Get D1 database
  const db = env.vault1;
  if (!db) {
    return jsonError("Database not available", 500);
  }

  // Validate JWT token
  let claims;
  try {
    claims = await verifyHs256Jwt(token, getJwtSecret(env));
  } catch (err) {
    return invalidTokenResponse("attachments.upload", err);
  }

  // Validate token claims match the request
  if (claims.cipher_id !== cipherId || claims.attachment_id !== attachmentId) {
    return invalidTokenResponse(
      "attachments.upload",
      `claims mismatch: expected cipher_id=${cipherId}, attachment_id=${attachmentId}; got cipher_id=${claims.cipher_id}, attachment_id=${claims.attachment_id}`
    );
  }

  const userId = claims.sub;
  const contextId =
    typeof claims.device === "string" && claims.device.length > 0
      ? claims.device
      : null;

  // Verify cipher belongs to user and is not deleted
  const cipher = await db
    .prepare("SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2")
    .bind(cipherId, userId)
    .first();

  if (!cipher) {
    return jsonError("Cipher not found", 404);
  }

  if (cipher.organization_id) {
    return jsonError("Organization attachments are not supported", 400);
  }

  if (cipher.deleted_at) {
    return jsonError("Cannot modify attachments for deleted cipher", 400);
  }

  // Fetch pending attachment record
  const pending = await db
    .prepare("SELECT * FROM attachments_pending WHERE id = ?1")
    .bind(attachmentId)
    .first();

  if (!pending) {
    return jsonError("Attachment not found or already uploaded", 404);
  }

  if (pending.cipher_id !== cipherId) {
    return jsonError("Attachment does not belong to cipher", 400);
  }

  const declaredSize = pending.file_size;
  if (typeof declaredSize !== "number" || declaredSize <= 0) {
    return jsonError("Invalid pending attachment size", 500);
  }

  // Build storage key
  const storageKey = `${cipherId}/${attachmentId}`;
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

  // Finalize upload: move pending -> attachments and touch revision timestamps
  const now = nowString();
  await db.batch([
    db
      .prepare(
        "INSERT INTO attachments (id, cipher_id, file_name, file_size, akey, created_at, updated_at, organization_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
      )
      .bind(
        attachmentId,
        cipherId,
        pending.file_name,
        declaredSize,
        pending.akey,
        pending.created_at || now,
        now,
        pending.organization_id || null
      ),
    db.prepare("DELETE FROM attachments_pending WHERE id = ?1").bind(attachmentId),
    db.prepare("UPDATE ciphers SET updated_at = ?1 WHERE id = ?2").bind(now, cipherId),
    db.prepare("UPDATE users SET updated_at = ?1 WHERE id = ?2").bind(now, userId),
  ]);

  if (env.NOTIFY_DO) {
    try {
      const id = env.NOTIFY_DO.idFromName("global");
      const stub = env.NOTIFY_DO.get(id);
      const response = await stub.fetch("https://notify.internal/publish-js-cipher", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          userId,
          updateType: 0, // SyncCipherUpdate
          cipherId,
          payloadUserId: userId,
          organizationId: pending.organization_id || null,
          revisionDate: now,
          contextId,
        }),
      });

      if (!response.ok) {
        console.error("NotifyDo publish failed for azure-upload finalize", response.status);
      }
    } catch (err) {
      console.error("NotifyDo publish threw during azure-upload finalize", err);
    }
  }

  return new Response(null, { status: 201 });
}

// Handle download with zero-copy streaming (R2) or ArrayBuffer (KV)
export async function handleDownload(request, env, cipherId, attachmentId, token) {
  // Check storage backend
  const backend = getStorageBackend(env);
  if (!backend) {
    return jsonError("Attachments are not enabled", 400);
  }

  // Get D1 database
  const db = env.vault1;
  if (!db) {
    return jsonError("Database not available", 500);
  }

  // Validate JWT token
  let claims;
  try {
    claims = await verifyHs256Jwt(token, getJwtSecret(env));
  } catch (err) {
    return invalidTokenResponse("attachments.download", err);
  }

  // Validate token claims match the request
  if (claims.cipher_id !== cipherId || claims.attachment_id !== attachmentId) {
    return invalidTokenResponse(
      "attachments.download",
      `claims mismatch: expected cipher_id=${cipherId}, attachment_id=${attachmentId}; got cipher_id=${claims.cipher_id}, attachment_id=${claims.attachment_id}`
    );
  }

  const userId = claims.sub;

  // Verify cipher belongs to user
  const cipher = await db
    .prepare("SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2")
    .bind(cipherId, userId)
    .first();

  if (!cipher) {
    return jsonError("Cipher not found", 404);
  }

  // Fetch attachment record
  const attachment = await db
    .prepare("SELECT * FROM attachments WHERE id = ?1")
    .bind(attachmentId)
    .first();

  if (!attachment) {
    return jsonError("Attachment not found", 404);
  }

  if (attachment.cipher_id !== cipherId) {
    return jsonError("Attachment does not belong to cipher", 400);
  }

  // Build storage key
  const storageKey = `${cipherId}/${attachmentId}`;
  const response = await streamDownloadFromStorage({
    env,
    storageKey,
    fallbackSize: attachment.file_size,
  });
  if (!response) {
    return jsonError("Attachment not found in storage", 404);
  }
  return response;
}
