# NETSHADOW

Plataforma de linha de comandos para inteligência de rede e auditoria de segurança. Utilize apenas em redes e dispositivos que possui ou para os quais tem autorização explícita.

## Requisitos

- Python 3.10 ou superior
- Git e [GitHub CLI](https://cli.github.com/) (`gh`)
- Acesso ao repositório privado `dinisbss/NETSHADOW`

Autentique-se no GitHub uma vez com `gh auth login`. Não coloque tokens ou passwords nos comandos.

## Instalação e arranque

Depois de autenticar o `gh`, execute um dos comandos seguintes numa janela de terminal. O comando clona o projeto, cria um ambiente Python isolado, instala as dependências e inicia a aplicação.

### Windows (PowerShell)

```powershell
gh repo clone dinisbss/NETSHADOW; if ($LASTEXITCODE -eq 0) { Set-Location NETSHADOW; powershell -ExecutionPolicy Bypass -File .\scripts\install_windows.ps1 }
```

### Linux

```bash
gh repo clone dinisbss/NETSHADOW && cd NETSHADOW && bash scripts/install_linux.sh
```

Para voltar a iniciar a aplicação depois da instalação:

```powershell
.\.venv\Scripts\netshadow.exe start
```

```bash
.venv/bin/netshadow start
```

Outros comandos disponíveis: `netshadow status`, `netshadow info` e `netshadow --help`.

O núcleo Python pode ser instalado sem Rust. A extensão Rust é opcional e será incluída quando o ambiente conseguir compilá-la.