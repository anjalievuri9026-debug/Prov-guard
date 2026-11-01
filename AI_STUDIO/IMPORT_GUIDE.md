# Import this project into Google AI Studio

## Important: ZIP vs. project import

This archive is a source-code bundle, not a one-click Google AI Studio project import. The current Google AI Studio Build-mode documentation describes **Import from GitHub** for bringing in an existing codebase. It does not document direct import of a whole project ZIP.

Official instructions: https://ai.google.dev/gemini-api/docs/aistudio-build-mode

## Recommended route: GitHub import

1. Extract `PROV-GUARD-AI-Studio-Bundle.zip` on your computer.
2. Create a new, private GitHub repository for the project.
3. Open a terminal in the extracted project folder and run:

   ```bash
   git init
   git add .
   git commit -m "Initial PROV-GUARD project bundle"
   git branch -M main
   git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
   git push -u origin main
   ```

4. Open Google AI Studio: https://aistudio.google.com/
5. Select **Build** mode.
6. In the prompt composer, select **+ / Add files → Import from GitHub**.
7. Choose the repository and branch you just pushed.
8. Once the project opens, open `AI_STUDIO/MASTER_PROMPT.md`, copy its contents, and paste them into the Build-mode chat.
9. Ask the agent to implement in phases and to run the existing test suite after each phase.

## Alternative: develop locally first

You can extract the ZIP and run the existing app locally with Node.js 22 or later:

```bash
npm install
npm run dev
```

Then use GitHub sync/import to move the project into AI Studio. This project uses Node's built-in `node:sqlite`, so use a Node.js 22+ runtime for local development.

## Security notes

- Do not commit `.env` files, API keys, private signing keys, real evidence files, or production databases.
- `.gitignore` excludes common local secrets and data folders. Review it before pushing.
- The sample accounts in the original DEIV project are for a local classroom demonstration only. Change or disable them before any real deployment.
- Use synthetic evidence for demos and tests. Do not upload private or sensitive evidence to an AI service unless you have authorization and an approved data-handling plan.
