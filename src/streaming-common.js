function httpError(message, status) {
  const error = new Error(message);
  error.status = status;
  return error;
}

export function nowString() {
  return new Date().toISOString();
}

export function jsonError(message, status) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function normalizeLogDetail(detail) {
  if (detail instanceof Error) {
    return detail.message;
  }
  return typeof detail === "string" ? detail : JSON.stringify(detail);
}

export function invalidTokenResponse(scope, detail) {
  console.warn(`[${scope}] Invalid token: ${normalizeLogDetail(detail)}`);
  return jsonError("Invalid token", 401);
}

export function getStorageBackend(env) {
  if (env.ATTACHMENTS_BUCKET) {
    return "r2";
  }
  if (env.ATTACHMENTS_KV) {
    return "kv";
  }
  return null;
}

export function parseRequiredContentLength(request) {
  const contentLengthHeader = request.headers.get("Content-Length");
  if (!contentLengthHeader) {
    throw httpError("Missing Content-Length header", 400);
  }

  const contentLength = Number.parseInt(contentLengthHeader, 10);
  if (Number.isNaN(contentLength) || contentLength <= 0) {
    throw httpError("Invalid Content-Length header", 400);
  }

  return contentLength;
}

export async function putRequestToStorage({
  env,
  request,
  storageKey,
  declaredSize,
}) {
  const contentLength = parseRequiredContentLength(request);
  if (contentLength !== declaredSize) {
    throw httpError(`Uploaded size (${contentLength}) does not match declared size (${declaredSize})`, 400);
  }

  const backend = getStorageBackend(env);
  if (!backend) {
    throw httpError("Storage backend is not enabled", 500);
  }

  const body = request.body;
  const contentType = request.headers.get("Content-Type");

  if (backend === "kv") {
    try {
      await env.ATTACHMENTS_KV.put(storageKey, body);
    } catch (err) {
      throw httpError(`Upload failed: ${err.message}`, 500);
    }
    return;
  }

  let r2Object;
  try {
    const putOptions = {};
    if (contentType) {
      putOptions.httpMetadata = { contentType };
    }
    r2Object = await env.ATTACHMENTS_BUCKET.put(storageKey, body, putOptions);
  } catch (err) {
    try {
      await env.ATTACHMENTS_BUCKET.delete(storageKey);
    } catch {
      // Ignore cleanup errors after failed upload.
    }
    throw httpError(`Upload failed: ${err.message}`, 500);
  }

  if (r2Object.size !== declaredSize) {
    try {
      await env.ATTACHMENTS_BUCKET.delete(storageKey);
    } catch {
      // Ignore cleanup errors after size mismatch.
    }
    throw httpError(`Uploaded size (${r2Object.size}) does not match declared size (${declaredSize})`, 400);
  }
}

export async function streamDownloadFromStorage({ env, storageKey, fallbackSize = null }) {
  const backend = getStorageBackend(env);
  if (!backend) {
    throw httpError("Storage backend is not enabled", 500);
  }

  if (backend === "kv") {
    const stream = await env.ATTACHMENTS_KV.get(storageKey, { type: "stream" });
    if (!stream) {
      return null;
    }

    const headers = new Headers();
    headers.set("Content-Type", "application/octet-stream");
    if (typeof fallbackSize === "number" && fallbackSize >= 0) {
      headers.set("Content-Length", fallbackSize.toString());
    }
    return new Response(stream, { status: 200, headers });
  }

  const r2Object = await env.ATTACHMENTS_BUCKET.get(storageKey);
  if (!r2Object) {
    return null;
  }

  const headers = new Headers();
  headers.set("Content-Type", r2Object.httpMetadata?.contentType || "application/octet-stream");
  headers.set("Content-Length", r2Object.size.toString());

  return new Response(r2Object.body, { status: 200, headers });
}
