# Contributing to SWA AI

Thank you for your interest in contributing to SWA AI!

## Code of Conduct & Responsible Disclosure
- SWA AI is strictly an **authorized cybersecurity platform**. All tools and probe plugins must incorporate scope policies, authorization boundaries, and non-destructive defaults.
- Never commit credentials, private API tokens, or exploit payloads designed to cause unrecoverable harm to target hosts.

## Development Workflow
1. Fork the repository on GitHub (`https://github.com/545e/snmk.git`).
2. Create a feature branch:
   ```bash
   git checkout -b feat/my-security-engine
   ```
3. Set up the local environment using the appropriate installer:
   - Windows: `install.bat` or `.\install.ps1`
   - Linux: `./install.sh`
   - macOS: `./install_macos.sh`
4. Run the automated test suite before opening a PR:
   ```bash
   pytest tests/
   ```
5. Ensure zero CodeQL security alerts and clean flake8 linting.
6. Open a Pull Request targeting `main`.

