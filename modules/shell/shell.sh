# open-rmm interactive session: startup script (bash rc file, or sh ENV).
cd / || true
PS1='open-rmm \h \w# '
echo "open-rmm: interactive session on $(hostname) as $(id -un)."
echo "Every command is recorded in the console's audit log. Type 'exit' to close."
