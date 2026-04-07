# 10 Agency Agents Subtree

## Why This Section Exists

The user requested full-repository documentation rather than scanner-only
documentation. That makes it important to describe `agency-agents/` clearly
without confusing it with the phishing scanner application.

## What It Is

`agency-agents/` is a large imported collection of AI agent definitions and
integration materials. Its own `README.md` presents it as "The Agency", a
catalog of specialized AI personas for domains such as:

- engineering
- design
- marketing
- sales
- product
- project management
- testing
- support
- strategy
- specialized domains

## Structure At A Glance

Key subtree areas include:

- `agency-agents/README.md`
- `agency-agents/engineering/`
- `agency-agents/design/`
- `agency-agents/testing/`
- `agency-agents/integrations/`
- `agency-agents/scripts/`
- other domain-specific folders grouped by specialty

## Relationship To The Scanner

The subtree appears to be repository content rather than runtime dependency.
Based on the files reviewed for this documentation:

- the phishing scanner does not import code from `agency-agents/`
- the scanner API does not route through this subtree
- the scanner UI does not depend on assets from this subtree

As a result, the subtree should be documented as ancillary repository content
with its own purpose and lifecycle.

## Why It Still Matters

Even though it is not part of scanner execution, it affects:

- repository size
- onboarding complexity
- documentation scope
- root-level tooling such as installation scripts

Ignoring it would make a full-repo handoff incomplete.

## Root-Level Installation Script

The root `install.sh` is related to the agency ecosystem rather than the
scanner. Its responsibilities include detecting supported tools and copying
integration files into tool-specific configuration locations.

This script should not be mistaken for the scanner setup path. Scanner setup is
much simpler and is documented in `README.md` with `pip install -r requirements.txt`
and `uvicorn app.api:app --reload`.

## Recommended Documentation Positioning

For future maintainers, the safest framing is:

- primary product: phishing scanner
- ancillary bundled content: `agency-agents`

If the repository evolves, it may be worth separating these concerns into
distinct repositories or documenting them under separate top-level handbooks.
