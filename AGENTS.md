# AGENTS.md

comment rules:
- Do not add code comments that restate what the code does. Names must carry meaning.
- Only comment to explain why code exists when the reason is invisible in the code (security, correctness trap, compatibility, ordering constraint). Keep it to one line.
- Prefer renaming, extracting a function, or narrowing scope over commenting.
- `//go:` directives and tool-generated markers (`// indirect`) are not comments; leave them alone.

