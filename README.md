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
- [x] Approvazione dei nuovi agenti, con approvazione automatica attivabile per singolo token
- [x] Rinnovo automatico del certificato dell'agente, con rotazione della chiave
- [x] Server in container Linux (Docker Compose), gateway non privilegiato e in sola lettura
- [x] Esecuzione dei moduli firmati, con SDK PowerShell e sh; moduli `sysinfo` e `script`
- [x] Coda dei job con consegna immediata e risultati che sopravvivono alle disconnessioni
- [x] Watchdog, task schedulato di controllo, aggiornamento automatico A/B con rollback, rollout per anelli
- [x] Servizio di firma dei job (`openrmm-signer`): firma solo comandi approvati con una nuova autenticazione MFA, verificata in modo indipendente
- [x] Console web con login Entra ID e MFA: agenti, approvazioni, comandi e script, job, moduli, token, registro attività
- [ ] Pacchetto MSI

## Installazione e sviluppo

- Installazione del server: [docs/INSTALLAZIONE.md](docs/INSTALLAZIONE.md)
- Configurazione di Microsoft Entra ID: [docs/ENTRA.md](docs/ENTRA.md)
- Scrivere e pubblicare moduli: [docs/MODULI.md](docs/MODULI.md)
- Aggiornamento dell'agente: [docs/AGGIORNAMENTI.md](docs/AGGIORNAMENTI.md)
- Sviluppo: [docs/SVILUPPO.md](docs/SVILUPPO.md)

```bash
make test
```

## Licenza

open-rmm è distribuito con licenza [GNU Affero General Public License v3.0](LICENSE). Chi modifica open-rmm e lo offre come servizio in rete deve rendere disponibile il codice sorgente delle proprie modifiche.
