# Installation

These skills are plain Markdown files. Installing them depends on which Claude surface you're using.

## Claude Code (CLI)

Claude Code looks for skills in `~/.claude/skills/` by default.

### Method 1: Direct copy

```bash
git clone https://github.com/elementalsouls/Claude-OSINT.git
cd Claude-OSINT

# Optional: populate full SKILL.md content from bundled full-skills (one-time after clone)
./scripts/sync-skill-content.sh

# Copy all 8 skills into your local Claude Code skills directory
mkdir -p ~/.claude/skills
cp -r skills/* ~/.claude/skills/

# Or install only the core recon pair (skip the six org-grade depth skills):
# cp -r skills/osint-methodology skills/offensive-osint ~/.claude/skills/
```

### Method 2: Symlink (stays in sync with git pull)

```bash
git clone https://github.com/elementalsouls/Claude-OSINT.git ~/.local/share/Claude-OSINT
mkdir -p ~/.claude/skills

# Symlink every skill directory (add/remove names to taste)
for s in ~/.local/share/Claude-OSINT/skills/*/; do
  ln -sf "$s" ~/.claude/skills/"$(basename "$s")"
done

cd ~/.local/share/Claude-OSINT
./scripts/sync-skill-content.sh   # one-time
```

Then `git -C ~/.local/share/Claude-OSINT pull && ./scripts/sync-skill-content.sh` periodically.

### Verify install

Start a new Claude Code session and type:

```
What ports should I probe to find Swagger or OpenAPI specs on a webapp?
```

Claude should pull the 28-path Swagger wordlist from the `offensive-osint` skill. If it doesn't, see [troubleshooting](#troubleshooting) below.

## Claude.ai (Pro / Team / Enterprise)

1. Open https://claude.ai
2. Create a new Project (or open an existing one).
3. Click **Add knowledge** → **Files**.
4. Upload the `SKILL.md` from each skill you want. At minimum the core pair — `skills/osint-methodology/SKILL.md` and `skills/offensive-osint/SKILL.md` — plus any of the six org-grade depth skills (`org-attack-surface`, `email-domain-security`, `exposure-risk-quantification`, `continuous-exposure-monitoring`, `cloud-saas-exposure`, `identity-provider-recon`) relevant to your engagement.
5. (Optional) Also upload `tests/smoke-test-prompts.md` for self-test reference.
6. Save.

In any conversation within that Project, the skills are available as system knowledge.

## Claude API (Anthropic SDK)

Attach the skill content as part of the system prompt:

```python
from anthropic import Anthropic

client = Anthropic()

with open("skills/osint-methodology/SKILL.md") as f:
    methodology = f.read()
with open("skills/offensive-osint/SKILL.md") as f:
    arsenal = f.read()

system_prompt = f"""You are an OSINT recon assistant for authorized red-team engagements.
You have access to the skills below and should reference them whenever relevant:

=== SKILL: osint-methodology ===
{methodology}

=== SKILL: offensive-osint ===
{arsenal}
"""

response = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=4096,
    system=system_prompt,
    messages=[{"role": "user", "content": "Plan a 4-hour external recon on acme.com (in-scope BB)"}]
)
print(response.content[0].text)
```

The example attaches the core pair. Attach any of the eight `SKILL.md` files the same way — concatenate the org-grade depth skills (`org-attack-surface`, `exposure-risk-quantification`, `identity-provider-recon`, etc.) into the system prompt when the task calls for them. All eight together are ~10,000 lines and still fit a 200K-context model.

## Claude Agent SDK / Cowork mode

These platforms typically auto-discover skills in `~/.claude/skills/`. Install via the Claude Code method above and they'll be available.

If you're building a custom agent with the SDK, attach SKILL.md content to your agent's system prompt as shown in the API method.

## Cursor / other AI IDEs

Most AI IDEs allow custom system-prompt injection. Use the API method above as a template.

## Troubleshooting

### "Claude doesn't seem to know about the skill"

1. Verify the file is at `~/.claude/skills/<skill-name>/SKILL.md` (not `~/.claude/skills/<skill-name>.md`).
2. Restart Claude Code.
3. In a fresh session, ask: *"Do you have access to a skill named offensive-osint?"* — Claude should confirm.
4. Check the YAML frontmatter is intact (begins with `---` and ends with `---`).

### "The skill loads but doesn't trigger on my prompt"

The skill's `triggers:` list controls auto-activation. If your prompt's wording isn't in the list, Claude may not pull the skill.

- Try rephrasing with a phrase from the SKILL.md `triggers:` list.
- If your phrasing is a common practitioner term, [open an issue](https://github.com/elementalsouls/Claude-OSINT/issues) to add it.

### "I get the structured-outline SKILL.md, not the full content"

By default we ship structured-outline SKILL.md files (small, fast to load). To get full inline content:

```bash
cd <repo>
./scripts/sync-skill-content.sh
```

This populates `skills/*/SKILL.md` with the full content from `docs/full-skills/*.SKILL.full.md`.

### "Skill is too large for my model's context"

All 8 skills together are ~10,000 lines / ~320 KB (the core pair alone is ~5,500 / ~150 KB). This fits comfortably in modern Claude context windows (200K+). If you're using an older model with smaller context:

- Use the structured-outline SKILL.md files (don't run sync-skill-content.sh).
- Or attach only the skills a task needs — each is self-contained (the core pair for recon, plus whichever org-grade depth skills apply).
- Or run a model with larger context (Claude Sonnet 4.6+, Opus 4.6+).

### "I want to filter the skill content"

Edit `skills/<skill-name>/SKILL.md` directly. Both files are plain Markdown. You can comment out sections you don't need or split them into multiple smaller skills.

## Verifying skill version

Each SKILL.md declares `version:` in the YAML frontmatter. Current: `osint-methodology` **2.3**, `offensive-osint` **2.2**, and the six org-grade depth skills **1.0**. Check via:

```bash
grep "^version:" skills/*/SKILL.md
```

## Uninstalling

```bash
# Remove every installed skill
rm -rf ~/.claude/skills/{osint-methodology,offensive-osint,org-attack-surface,email-domain-security,exposure-risk-quantification,continuous-exposure-monitoring,cloud-saas-exposure,identity-provider-recon}
```

Or remove the symlinks if you used method 2 above.
