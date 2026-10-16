# open-rmm

Software RMM (Remote Monitoring and Management) open source, progettato con la sicurezza come requisito primario.

- **Agente** per Windows (client e server) e Linux, installabile via GPO, modulare: le nuove funzionalità arrivano come moduli firmati, senza aggiornare l'agente.
- **Console** centralizzata, ospitabile presso il cliente, multi-tenant e federabile.
- **Comunicazioni solo in uscita** dagli endpoint, con mTLS e CA privata in pinning.

Il progetto è nelle prime fasi. L'architettura completa è in [docs/ARCHITETTURA.md](docs/ARCHITETTURA.md).

## Stato

Fase 0 (fondamenta), in corso:

- [x] Protocollo agente ↔ console (gRPC, [proto/openrmm/v1/agent.proto](proto/openrmm/v1/agent.proto))
- [x] PKI: root CA offline, CA degli agenti, certificati per agente con identità tenant/agente
- [x] Enrollment con token monouso (salvato solo come hash, limitato per IP)
- [x] Gateway mTLS: senza certificato valido si raggiunge solo l'enrollment
- [x] Agente: chiave generata in locale, connessione persistente, heartbeat, riconnessione con backoff
- [x] Agente come servizio Windows con ripartenza automatica; unit systemd per Linux
- [x] Configurazione da file, registro (MSI) e GPO (`HKLM\SOFTWARE\Policies\open-rmm`)
- [x] Verifica dei job firmati (Ed25519, scadenza, destinatario, anti-replay persistente)
- [x] PostgreSQL con isolamento per tenant (row-level security) e audit log a catena di hash non modificabile
- [ ] Rinnovo automatico del certificato dell'agente
- [ ] Esecuzione dei moduli firmati e SDK PowerShell
- [ ] Watchdog, task schedulato di controllo, aggiornamento automatico A/B
- [ ] Servizio di firma dei job (`openrmm-signer`)
- [ ] Console web con login Entra ID e MFA
- [ ] Pacchetto MSI

## Sviluppo

Vedi [docs/SVILUPPO.md](docs/SVILUPPO.md).

```bash
make test
```
