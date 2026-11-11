# Tempra RMM interactive session: startup script (bash rc file, or sh ENV).
cd / || true
PS1='tempra \h \w# '
echo "Tempra RMM: interactive session on $(hostname) as $(id -un)."
echo "Every command is recorded in the console's audit log. Type 'exit' to close."
