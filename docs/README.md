# Project Documentation Suite

This documentation set is the comprehensive reference for the `Capstone` workspace.
It is written for a mixed audience of developers, operators, reviewers, and
project stakeholders who need both a quick understanding of the phishing
scanner and a factual map of the wider repository.

## Documentation Goals

- Explain what the phishing scanner does, how it works, and how to operate it.
- Separate the scanner runtime from ancillary repository content.
- Provide enough detail for project handoff, maintenance, and capstone review.
- Keep the documentation reusable as source material for generated deliverables.

## Recommended Reading Order

1. `docs/01-project-overview.md`
2. `docs/02-repository-tour.md`
3. `docs/03-system-architecture.md`
4. `docs/04-api-reference.md`
5. `docs/05-scanner-modules.md`
6. `docs/06-threat-intelligence-and-caching.md`
7. `docs/07-web-ui-and-user-experience.md`
8. `docs/08-baseline-evaluation-and-data.md`
9. `docs/09-development-testing-and-operations.md`
10. `docs/10-agency-agents-subtree.md`
11. `docs/11-risks-limitations-and-roadmap.md`
12. `docs/12-ml-lab-and-classifier.md`

## Generated Document

The Markdown pages in this folder are also the source for the compiled Word
document at:

- `docs/project-documentation.docx`

To regenerate the compiled document after updating the Markdown pages, run:

```bash
python scripts/generate_project_documentation.py
```

## Scope Boundary

The repository contains two clearly different concerns:

- The phishing scanner web service, which is the main application in this
  workspace.
- The `agency-agents` subtree, which is a large imported collection of agent
  definitions and integration assets.

Most runtime, API, UI, and testing behavior described in this suite belongs to
the phishing scanner. The ancillary content is documented separately so readers
do not mistake it for part of the scanner execution path.
