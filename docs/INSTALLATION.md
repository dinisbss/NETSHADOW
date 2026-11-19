
# NETSHADOW — Installation Guide

## 1. Requirements

NETSHADOW requires:

- Python 3.10 or newer.
- pip.
- Git.
- GitHub CLI (`gh`) authenticated for the private repository.
- Windows 10/11 or a compatible Linux distribution.

Optional:
- Rust toolchain.
- Cargo.
- Maturin.

## Instalação rápida

Autentique-se no GitHub uma vez com `gh auth login`. Depois, execute o comando do teu sistema para clonar, instalar e iniciar:

Windows (PowerShell):

```powershell
gh repo clone dinisbss/NETSHADOW; if ($LASTEXITCODE -eq 0) { Set-Location NETSHADOW; powershell -ExecutionPolicy Bypass -File .\scripts\install_windows.ps1 }
```

Linux:

```bash
gh repo clone dinisbss/NETSHADOW && cd NETSHADOW && bash scripts/install_linux.sh
```

Para voltar a iniciar depois da instalação, executa `.\.venv\Scripts\netshadow.exe start` no Windows ou `.venv/bin/netshadow start` no Linux. Não coloques tokens ou passwords nos comandos.

## 2. Windows Installation

### Step 1 — Verify Python

Open PowerShell:

```powershell
py --version
```

### Step 2 — Enter the Project Directory

```powershell
cd NETSHADOW
```

### Step 3 — Create a Virtual Environment

```powershell
py -m venv .venv
```

### Step 4 — Activate the Environment

```powershell
.\.venv\Scripts\Activate.ps1
```

### Step 5 — Upgrade pip

```powershell
py -m pip install --upgrade pip
```

### Step 6 — Install the Project

```powershell
py -m pip install -e .
```

## 3. Kali Linux Installation

### Step 1 — Verify Python

```bash
python3 --version
```

### Step 2 — Enter the Project Directory

```bash
cd NETSHADOW
```

### Step 3 — Create a Virtual Environment

```bash
python3 -m venv .venv
```

### Step 4 — Activate the Environment

```bash
source .venv/bin/activate
```

### Step 5 — Upgrade pip

```bash
python -m pip install --upgrade pip
```

### Step 6 — Install the Project

```bash
python -m pip install -e .
```

## 4. Configuration

Review the configuration files:

- config/settings.yaml
- config/logging.yaml
- config/security.yaml
- config/networks.yaml

The application should retain SAFE mode as its default.

Do not place credentials or secrets directly in configuration files.

## 5. Rust Components (Optional)

Rust components are optional.

Verify the installation:

```bash
rustc --version
cargo --version
```

Install Maturin inside the virtual environment:

```bash
python -m pip install maturin
```

Build the Rust extension from the directory containing the Rust Cargo.toml:

```bash
maturin develop --release
```

The Python application must continue working when the Rust extension is unavailable.

## 6. Verify Installation

Run the test suite:

```bash
python -m pytest -v
```

Check the application entry point:

```bash
python main.py --help
```

The exact command options depend on the implemented CLI.

## 7. Database

NETSHADOW uses SQLite.

The database is initialized by the application.

Ensure the application has permission to access its configured data directory.

## 8. Troubleshooting

### Python Not Found

Verify that Python is installed and available in PATH.

### Virtual Environment Activation Failed

On Windows, review PowerShell execution policies.

On Linux, verify that the venv package is installed.

### Missing Dependencies

Activate the virtual environment and install the project dependencies again.

### Rust Extension Unavailable

Verify the Rust toolchain and Maturin installation.

The Python fallback should remain available.

### Database Errors

Verify directory permissions and database configuration.

## 9. Updating NETSHADOW

Before updating:

1. Review the changes.
2. Back up important application data.
3. Update dependencies in the virtual environment.
4. Run the test suite.
5. Verify database compatibility.

## 10. Safe Operation

Always use networks and systems that you own or are explicitly authorized to assess.

Keep SAFE mode enabled unless an explicitly authorized operation is required.
