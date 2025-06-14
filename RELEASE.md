

# 🌐 The Greater Internet Project  
**Release Version:** Open Beta 0.1.0  
**License:** MIT  
**Status:** Active open beta (early-stage, use with caution)

---

## 📦 Current Implementations

### `httpe_client`
- Establishes connections over either **EDOI-NET** or **normal Internet**.
- **Only compatible with `httpe_server`** (client-to-client support is planned in a future release).
- **Normal mode:** Stable, but caution is advised.
- **EDOI-NET mode:** Generally stable, but may occasionally drop packets silently. Restarting the client typically resolves the issue. Root cause is under investigation.

### `httpe_server`
- Accepts connections **only from `httpe_client`** — by design.
- Compatible with both **EDOI-NET** and **normal Internet**.
- **Normal mode:** Stable.
- **EDOI-NET mode:** May rarely "lock" and stop processing packets. Potential causes:
  - OS-level interference (e.g., Windows firewall or rate-limiting).
  - Silent exceptions within EDOI-NET nodes that lock up routing paths.

### `edoi_net`
- Asynchronous node-based routing protocol.
- Tested with **200 nodes**, each with **5 neighbors**, on a LAN.
- Round-trip time: **0.1–0.2 seconds** (raw code delay; excludes network latency).
- Current issues:
  - Debug messages appear even when not in debug mode.
  - `run_output.log` path is hardcoded (to be fixed).
  - Some errors may fail silently.

---

## 🧰 Utility Scripts

### `certgen.py`
- Generates all necessary certificates and key files.
- **Outputs files to the current working directory**.  
  *(This will change in the next 2 releases.)*
- Default hostname: `localhost`.
- See source code for additional customization.

### `time_analyze.py`
- Used for analyzing EDOI-NET performance logs.
- To use:
  1. Rename or copy `run_output.log` to `time.txt`.
  2. Run the script to generate a detailed report:
     - Bottleneck detection
     - Time delays
     - Full packet path analysis

---

## 🗂️ Project Structure (for pip installation)

Each module is laid out as:

```

{package_name}/
├── {package_name}/
│   ├── **init**.py
│   └── \*.py
└── pyproject.toml

````

To install a module in development mode:
```bash
pip install -e .
````

### Additional Notes:

* `httpe_core` is not designed for standalone use, except for:

  * `httpe_core.httpe_fernet`: A **custom AES-256 Fernet** implementation *(not peer-reviewed)*.
* `from {package} import *` may not work; use `import {package}` directly.
* **Known Issue:** Pylance may not support autocomplete for editable installs.

---

## ⚠️ Known Issues

* **Specs are outdated**: Please avoid relying on them until the first stable release.
* **EDOI-NET client packet drops**: Ongoing investigation.
* **EDOI-NET server lockups**: Occasional, rare, and under analysis.
* **Logging**: Debug messages still print; log path is not yet configurable.
* **Autocomplete issues**: Pylance has trouble with `pip install -e .` setups.

---

## 🙋 Final Notes

This project is actively developed by a solo 18-year-old developer working part-time. While it's progressing steadily, features and fixes may roll out gradually. Thank you for trying it out!

Pull requests, issue reports, and feedback are welcome once the public infrastructure (e.g., GitHub Issues and Discussions) is in place.

---
