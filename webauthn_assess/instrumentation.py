from __future__ import annotations

import json

from .config import MutationConfig


def build_init_script(mutation: MutationConfig) -> str:
    cfg = json.dumps(mutation.as_script_options(), separators=(",", ":"))
    return f"""
(() => {{
  if (window.__webauthnAssessInstalled) {{
    return;
  }}
  window.__webauthnAssessInstalled = true;

  const config = {cfg};
  const state = {{
    seq: 0,
    events: [],
    config,
  }};

  function b64urlFromBytes(bytes) {{
    let binary = "";
    for (let i = 0; i < bytes.length; i += 1) {{
      binary += String.fromCharCode(bytes[i]);
    }}
    return btoa(binary).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/g, "");
  }}

  function bufferToB64url(value) {{
    if (value == null) return null;
    if (value instanceof ArrayBuffer) {{
      return b64urlFromBytes(new Uint8Array(value));
    }}
    if (ArrayBuffer.isView(value)) {{
      const view = value;
      return b64urlFromBytes(new Uint8Array(view.buffer, view.byteOffset, view.byteLength));
    }}
    return null;
  }}

  function cloneForLog(value, seen = new WeakSet()) {{
    if (value == null) return value;
    if (typeof value === "function") return undefined;

    const buf = bufferToB64url(value);
    if (buf !== null) return buf;

    if (Array.isArray(value)) {{
      return value.map((item) => cloneForLog(item, seen));
    }}

    if (typeof value === "object") {{
      if (seen.has(value)) return "[Circular]";
      seen.add(value);
      const out = {{}};
      for (const key of Object.keys(value)) {{
        out[key] = cloneForLog(value[key], seen);
      }}
      return out;
    }}

    return value;
  }}

  function serializeCredential(cred) {{
    if (!cred) return null;
    const response = cred.response || {{}};
    return {{
      id: cred.id,
      rawId: bufferToB64url(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || null,
      clientExtensionResults: cloneForLog(cred.getClientExtensionResults ? cred.getClientExtensionResults() : {{}}),
      response: {{
        attestationObject: bufferToB64url(response.attestationObject),
        clientDataJSON: bufferToB64url(response.clientDataJSON),
        authenticatorData: bufferToB64url(response.authenticatorData),
        signature: bufferToB64url(response.signature),
        userHandle: bufferToB64url(response.userHandle),
      }},
    }};
  }}

  function maybeMutateOptions(ceremony, options) {{
    if (!config.enabled || !options || !options.publicKey) {{
      return options;
    }}
    const pk = options.publicKey;
    if (config.rpIdOverride) {{
      if (ceremony === "register" && pk.rp && typeof pk.rp === "object") {{
        pk.rp.id = config.rpIdOverride;
      }}
      if (ceremony === "auth") {{
        pk.rpId = config.rpIdOverride;
      }}
    }}
    if (
      ceremony === "register" &&
      Number.isInteger(config.algorithmOverride)
    ) {{
      pk.pubKeyCredParams = [{{ type: "public-key", alg: config.algorithmOverride }}];
    }}
    return options;
  }}

  function logEvent(stage, ceremony, payload) {{
    state.seq += 1;
    const item = {{
      seq: state.seq,
      ts: Date.now(),
      stage,
      ceremony,
      ...payload,
    }};
    state.events.push(item);
  }}

  if (navigator.credentials && navigator.credentials.create) {{
    const originalCreate = navigator.credentials.create.bind(navigator.credentials);
    navigator.credentials.create = async function(options) {{
      const mutatedOptions = maybeMutateOptions("register", options);
      logEvent("options", "register", {{ options: cloneForLog(mutatedOptions) }});
      const credential = await originalCreate(mutatedOptions);
      logEvent("result", "register", {{ credential: serializeCredential(credential) }});
      return credential;
    }};
  }}

  if (navigator.credentials && navigator.credentials.get) {{
    const originalGet = navigator.credentials.get.bind(navigator.credentials);
    navigator.credentials.get = async function(options) {{
      const mutatedOptions = maybeMutateOptions("auth", options);
      logEvent("options", "auth", {{ options: cloneForLog(mutatedOptions) }});
      const credential = await originalGet(mutatedOptions);
      logEvent("result", "auth", {{ credential: serializeCredential(credential) }});
      return credential;
    }};
  }}

  window.__webauthnAssess = {{
    getEvents: () => state.events.slice(),
    clearEvents: () => {{
      state.events = [];
    }},
  }};
}})();
""".strip()
