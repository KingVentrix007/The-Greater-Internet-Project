
# 🚀 Getting Started

## ✅ Prerequisites

- Ensure you have **Python ≥ 3.12.3**
- `git` and `pip` should be installed and available in your PATH

---

## 📦 Installation Guide

### 1. Clone the Repository

```bash
git clone https://github.com/KingVentrix007/The-Greater-Internet-Project.git
cd The-Greater-Internet-Project
````

### 2. Switch to a Stable Branch

Replace `X.X.X` with the actual version number:

```bash
git checkout stable-vX.X.X
# Or
git checkout open-beta-vX.X.X
```

### 3. Install Project Dependencies

```bash
pip install -r requirements.txt
```

---

## 🧱 Build and Install Project Components

### 4. Core Module

```bash
cd httpe_core
pip install .
# Or, for development mode:
pip install -e .
```

### 5. Client Module

```bash
cd ../httpe_client
pip install .
# Or, for development mode:
pip install -e .
```

### 6. Server Module

```bash
cd ../httpe_server
pip install .
# Or, for development mode:
pip install -e .
```

### 7. EDOI Nodes Module

```bash
cd ../edoi_net
pip install .
# Or, for development mode:
pip install -e .
```

---

## 🧪 Optional: ToxiProxy for Testing

### 🔧 Install ToxiProxy

#### On Windows

Download the latest stable release:
👉 [ToxiProxy Releases (Windows)](https://github.com/Shopify/toxiproxy/releases)

Look for:
`toxiproxy-server-windows-amd64.exe`

#### On Linux

Download the appropriate binary from:
👉 [ToxiProxy Releases (Linux)](https://github.com/Shopify/toxiproxy/releases)

Example filename:
`toxiproxy_X.XX.X_linux_amd64.<extension>`

> **Note:** If the downloaded version fails to run, try version `v2.12.0`:
> 👉 [Download ToxiProxy v2.12.0](https://github.com/Shopify/toxiproxy/releases/tag/v2.12.0)

---

## 🛠️ Next Steps

- Edit the source code as needed
- Or run the demo code to explore the system functionality
