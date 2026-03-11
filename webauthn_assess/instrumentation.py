from __future__ import annotations

import json

from .config import MutationConfig


def build_init_script(mutation: MutationConfig, verbose: bool = False) -> str:
    cfg = mutation.as_script_options()
    cfg["debugConsole"] = bool(verbose)
    payload = json.dumps(cfg, separators=(",", ":"))
    return f"""
(() => {{
  if (window.__webauthnAssessInstalled) {{
    return;
  }}
  window.__webauthnAssessInstalled = true;

  const config = {payload};
  const state = {{
    seq: 0,
    events: [],
    installs: [],
    installFailures: [],
  }};

  function debug(message, data) {{
    if (!config.debugConsole) return;
    try {{
      if (typeof data === "undefined") {{
        console.debug("[webauthn-assess-js]", message);
      }} else {{
        console.debug("[webauthn-assess-js]", message, data);
      }}
    }} catch (_err) {{
      // ignored
    }}
  }}

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
      clientExtensionResults: cloneForLog(
        cred.getClientExtensionResults ? cred.getClientExtensionResults() : {{}}
      ),
      response: {{
        attestationObject: bufferToB64url(response.attestationObject),
        clientDataJSON: bufferToB64url(response.clientDataJSON),
        authenticatorData: bufferToB64url(response.authenticatorData),
        signature: bufferToB64url(response.signature),
        userHandle: bufferToB64url(response.userHandle),
      }},
    }};
  }}

  function frameContext() {{
    return {{
      href: String(location.href || ""),
      isTop: window === window.top,
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
    if (ceremony === "register" && Number.isInteger(config.algorithmOverride)) {{
      pk.pubKeyCredParams = [{{ type: "public-key", alg: config.algorithmOverride }}];
    }}
    if (ceremony === "register" && config.attestationRequestModeOverride) {{
      pk.attestation = config.attestationRequestModeOverride;
    }}
    return options;
  }}

  function logEvent(stage, ceremony, payload2) {{
    state.seq += 1;
    const item = {{
      seq: state.seq,
      ts: Date.now(),
      stage,
      ceremony,
      ...payload2,
    }};
    state.events.push(item);
    debug(`${{stage}}/${{ceremony}}`, item);
  }}

  function patchCredentialsTarget(target, label) {{
    if (!target) {{
      state.installFailures.push({{ ts: Date.now(), label, reason: "missing-target" }});
      return;
    }}
    if (target.__webauthnAssessWrapped) {{
      return;
    }}
    target.__webauthnAssessWrapped = true;

    const installRecord = {{
      ts: Date.now(),
      label,
      createWrapped: false,
      getWrapped: false,
      frame: frameContext(),
    }};

    if (typeof target.create === "function") {{
      const originalCreate = target.create;
      target.create = async function(options) {{
        const mutatedOptions = maybeMutateOptions("register", options);
        const synthetic = Boolean(originalCreate.__webauthnAssessSynthetic);
        logEvent("call", "register", {{
          method: "create",
          options: cloneForLog(mutatedOptions),
          source: synthetic ? "synthetic" : "browser",
          synthetic,
          frame: frameContext(),
        }});
        try {{
          const credential = await originalCreate.call(this, mutatedOptions);
          logEvent("result", "register", {{
            method: "create",
            credential: serializeCredential(credential),
            source: synthetic ? "synthetic" : "browser",
            synthetic,
            frame: frameContext(),
          }});
          return credential;
        }} catch (err) {{
          logEvent("error", "register", {{
            method: "create",
            source: synthetic ? "synthetic" : "browser",
            synthetic,
            frame: frameContext(),
            error: {{
              name: err && err.name ? String(err.name) : "Error",
              message: err && err.message ? String(err.message) : String(err),
            }},
          }});
          throw err;
        }}
      }};
      installRecord.createWrapped = true;
    }}

    if (typeof target.get === "function") {{
      const originalGet = target.get;
      target.get = async function(options) {{
        const mutatedOptions = maybeMutateOptions("auth", options);
        const synthetic = Boolean(originalGet.__webauthnAssessSynthetic);
        logEvent("call", "auth", {{
          method: "get",
          options: cloneForLog(mutatedOptions),
          source: synthetic ? "synthetic" : "browser",
          synthetic,
          frame: frameContext(),
        }});
        try {{
          const credential = await originalGet.call(this, mutatedOptions);
          logEvent("result", "auth", {{
            method: "get",
            credential: serializeCredential(credential),
            source: synthetic ? "synthetic" : "browser",
            synthetic,
            frame: frameContext(),
          }});
          return credential;
        }} catch (err) {{
          logEvent("error", "auth", {{
            method: "get",
            source: synthetic ? "synthetic" : "browser",
            synthetic,
            frame: frameContext(),
            error: {{
              name: err && err.name ? String(err.name) : "Error",
              message: err && err.message ? String(err.message) : String(err),
            }},
          }});
          throw err;
        }}
      }};
      installRecord.getWrapped = true;
    }}

    state.installs.push(installRecord);
  }}

  patchCredentialsTarget(navigator.credentials, "navigator.credentials");
  if (typeof CredentialsContainer !== "undefined" && CredentialsContainer.prototype) {{
    patchCredentialsTarget(CredentialsContainer.prototype, "CredentialsContainer.prototype");
  }}

  window.__webauthnAssess = {{
    getEvents: () => state.events.slice(),
    getStatus: () => {{
      return {{
        installs: state.installs.slice(),
        installFailures: state.installFailures.slice(),
        eventCount: state.events.length,
      }};
    }},
    clearEvents: () => {{
      state.events = [];
    }},
  }};
}})();
""".strip()
