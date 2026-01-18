# JJ Workflow Example

This demonstrates the complete jj + jj-spr workflow for the OBJECTS Protocol.

## Quick Reference

```bash
# 1. Make changes and commit
jj describe -m "feat: your feature"

# 2. Create PR
jj spr diff

# 3. After approval, merge
jj spr land
```

## Benefits

- **Stack commits** during development
- **Curate before review** with split/squash
- **Automated PR management** with jj-spr
- **Everything is undoable** with jj undo
