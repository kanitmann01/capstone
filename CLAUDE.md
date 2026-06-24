## Design Context

### Users
Primary users are general employees and non-technical users scanning suspicious links before opening them. They need quick confidence cues and clear outcomes without requiring deep security expertise.

### Brand Personality
Fast, technical, and trustworthy. Interactions should feel responsive and competent while avoiding alarmist behavior unless risk is high.

### Aesthetic Direction
Functional and focused with moderate motion. Prioritize crisp feedback and purposeful transitions over decorative animation. Keep motion lightweight for smooth performance on lower-end devices. Respect reduced-motion preferences with a softer alternative that keeps tiny fades only.

### Design Principles
1. Confirm user actions immediately with visible feedback.
2. Use motion only to clarify state changes and progress.
3. Keep interactions fast and unobtrusive for repeat use.
4. Preserve readability and confidence over visual flair.
5. Favor GPU-friendly animation (`transform`, `opacity`) to protect responsiveness.

## Agent skills

### Issue tracker

GitHub Issues at kanitmann01/capstone. See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary (needs-triage, needs-info, ready-for-agent, ready-for-human, wontfix). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout with CONTEXT.md and docs/adr/ at repo root. See `docs/agents/domain.md`.
