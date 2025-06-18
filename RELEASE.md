# 🌐 The Greater Internet Project

**Release Version:** Open Beta 1.0.0
**License:** MIT
**Status:** Active Open Beta *(early-stage — use with caution)*

---

## 📦 Current Implementations

### `httpe_client`

* Establishes secure connections over either **EDOI-NET** or the **normal Internet**.
* **Only compatible with `httpe_server`**
* **Normal Mode:** Stable, but use cautiously.
* **EDOI-NET Mode:** Generally stable, but may occasionally drop packets.

  * ⚠️ Packet loss should be detected and trigger visible warnings.

---

### `httpe_server`

* Accepts connections **only from `httpe_client`** — by design.
* Compatible with both **EDOI-NET** and the **normal Internet**.
* **Normal Mode:** Stable.
* **EDOI-NET Mode:** May occasionally "lock" and stop processing packets.

  * **Possible causes:**

    * OS-level interference (e.g., Windows Firewall, rate-limiting, etc.)

---

### `edoi_net`

* Asynchronous, node-based routing protocol.
* Tested with **200 nodes**, each with **5 neighbors**, over LAN.
* **Round-trip time:** 0.1–0.2 seconds *(raw processing delay only — excludes actual network latency)*
* **Known Issues:**

  * Debug messages are printed even when not in debug mode.
  * Log file path (`run_output.log`) is currently hardcoded. *(Needs config support)*

---

## 🧰 Utility Scripts

### `certgen.py`

* Generates required certificates and key files for the system.
* Minimal user input required.
* Intended for quick dev/test setups.

---

## 🗂️ Project Structure (for pip development install)

All modules follow this structure:

```txt
{package_name}/
├── {package_name}/
│   ├── __init__.py
│   └── *.py
└── pyproject.toml
```

To install a module in development mode:

```bash
pip install -e .
```

> ⚠️ Note:
>
> * `httpe_core` is **not** designed for standalone use — with one exception:
>
>   * `httpe_core.httpe_fernet`: Custom AES-256-based Fernet encryption (*not peer-reviewed*).
> * `from {package} import *` may not work. Use direct imports: `import {package}`.
> * Some IDEs (e.g., **Pylance**) may not support autocomplete for editable installs (`-e`).

---

## ✨ New Features

* **Client event hooks**: Use `.on("event", handler)` or `@on("event")` to bind custom event handlers.
* **`httpe_sync`**: A synchronous wrapper for the client.

  * Drop-in replacement for `requests`, with support for both `http(s)://` and `edoi://` protocols.
* **Content negotiation**:

  * Client and server now support `Content-Type` and `Accept` headers (to varying degrees).
* **Error handling improvements**:

  * Far more stable client; critical bugs resolved.
  * Many edge-case errors now caught cleanly.

---

## ⚠️ Known Issues

* **Specs are outdated** — please avoid relying on them until the first stable release.
* **IDE support** — Autocomplete may break when using `pip install -e .`.

---

## 🙋 Final Notes

This project is being built by a solo **18-year-old developer** working part-time.
Development is ongoing, and new features or fixes may take time to roll out.

Feedback, issue reports, and pull requests will be welcome once the public infrastructure (e.g., GitHub Issues, Discussions) is fully set up.

Thanks for checking it out!

---
