# Domain Documentation Layout

**Layout:** Single-context

**Consumer rules for engineering skills:**

1. **CONTEXT.md** at repo root contains the project's domain language, ubiquitous terms, and core concepts. Skills read this first to understand the domain.

2. **docs/adr/** contains Architecture Decision Records (ADRs) documenting past architectural decisions. Skills reference these to maintain consistency with established patterns.

3. When exploring code, skills prioritize understanding domain language from CONTEXT.md before making architectural recommendations.
