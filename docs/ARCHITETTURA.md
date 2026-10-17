# open-rmm — Documento di architettura

> Stato: bozza v0.9 — 2026-10-17
> Primo cliente: ~200 endpoint Windows (client e server), parco misto Dell / Lenovo / Acer, BitLocker diffuso, console ospitata presso il cliente e raggiungibile da internet, portatili anche fuori sede.

---

## 1. Obiettivi e vincoli

| # | Requisito | Note |
|---|-----------|------|
| R1 | Windows client/server e Linux | Windows prioritario, Linux in fase 4 |
| R2 | Installazione via GPO | Pacchetto MSI con parametri via MST / registro |
| R3 | Sicurezza come requisito primario | Vedi §6 |
| R4 | Ripartenza automatica in caso di crash | Service recovery + watchdog + task schedulato |
| R5 | Console centralizzata | Tenant-aware dal primo giorno, federabile |
| R6 | Windows Update: verifica e installazione | Modulo prioritario |
| R7 | Inventario hardware e software, log di accesso | MVP, vedi §8.1 |
| R8 | Aggiornamenti firmware e software (winget) | Fasi 2–3 |
| R9 | Esecuzione comandi PowerShell dalla console | MVP, con controlli di sicurezza rafforzati |
| R10 | **Agente modulare: nuove funzionalità senza aggiornare l'agente** | Principio architetturale cardine, vedi §3 |
| R11 | Aggiornamento automatico dell'agente | A/B con rollback, vedi §5 |
| R12 | Accesso alla console solo con utenti Microsoft 365 (Entra ID), MFA obbligatoria | Vedi §6.6 |
| R13 | Console ospitata presso il cliente e raggiungibile da internet; **tutte le comunicazioni partono dagli endpoint** | Vedi §4 e §6.7 |
| R15 | Riavvii configurabili per gruppo di endpoint | Vedi §8.6 |
| R14 | Coesistenza con WSUS e Intune | Oggi non presenti, ma previsti. Vedi §8.2 |

**Principi guida**

1. **Il core dell'agente non conosce nessuna funzionalità.** Sa solo comunicare, autenticarsi, verificare firme ed eseguire moduli. Windows Update, inventario, winget: tutto è un modulo.
2. **Nessuna porta in ascolto sugli endpoint.** Tutte le connessioni partono dall'agente. La console non apre mai connessioni verso i PC.
3. **Una console compromessa non deve bastare per eseguire codice arbitrario** sugli endpoint, nei limiti del possibile (§6.3).
4. **Tenant-aware dal giorno zero**, anche con un solo cliente.

---

## 2. Componenti

```
┌──────────────────────────── ENDPOINT ────────────────────────────┐
│                                                                   │
│  openrmm-watchdog (servizio)  ──sorveglia/aggiorna──►  openrmm-agent      │
│                                                   (servizio, core)│
│                                                     │   ▲         │
│                         esegue moduli firmati ──────┘   │ named   │
│                         (sottoprocessi)                 │ pipe    │
│                                                 openrmm-userhelper    │
│                                                 (sessione utente) │
└───────────────────────────────┬───────────────────────────────────┘
                                │ gRPC su HTTP/2, mTLS, porta 443
                                │ (connessione avviata dall'agente)
┌───────────────────────────────▼──────────────── CONSOLE ─────────┐
│  openrmm-gateway  ──►  openrmm-server (API, logica, job queue)  ──► Postgres
│                         │                                         │
│                         ├──► openrmm-signer (servizio firma, isolato) │
│                         └──► Web UI (pagine generate dal server)  │
│  openrmm-repo: archivio moduli, pacchetti agente, cache cataloghi     │
└───────────────────────────────────────────────────────────────────┘
```

### 2.1 Endpoint

| Componente | Ruolo | Frequenza aggiornamento attesa |
|---|---|---|
| `openrmm-agent` | Core: trasporto, identità, job runner, module manager, scheduler locale, coda offline | Rara (solo protocollo/sicurezza) |
| `openrmm-watchdog` | Controlla salute dell'agente, lo riavvia, applica gli aggiornamenti dell'agente con rollback | Molto rara |
| `openrmm-userhelper` | Processo nella sessione utente: notifiche, richieste di riavvio, esecuzione di moduli in contesto utente (app per-utente, winget per-utente) | Rara |
| Moduli | Tutte le funzionalità | Frequente, **senza toccare l'agente** |

### 2.2 Console

| Componente | Tecnologia |
|---|---|
| Backend `openrmm-server` | Go |
| Database | PostgreSQL con Row-Level Security per `tenant_id` |
| Job queue | Su Postgres (es. libreria *river*), niente broker esterno per partire |
| Web UI | Pagine generate dal server Go (html/template), nessun JavaScript di terze parti, CSP restrittiva |
| Autenticazione operatori | Solo Entra ID (Microsoft 365) via OIDC; MFA sempre obbligatoria (§6.6) |
| `openrmm-signer` | Processo separato con privilegi minimi, unico detentore della chiave di firma dei job (§6.3) |
| Deploy | Docker Compose su una singola VM **presso il cliente** (adeguato per 200–2000 endpoint) |

### 2.3 Struttura del repository (monorepo)

```
/proto                 definizioni protobuf (agente ↔ console)
/gen                   codice generato da buf (committato)
/agent/cmd             eseguibili dell'agente (openrmm-agent; poi watchdog e userhelper)
/console/cmd           eseguibili della console (openrmm-gateway, openrmm-admin; poi server e signer)
/internal
  /pki /signing /tlsconf /ids     crittografia e identità condivise
  /agent/...           core dell'agente: config, identity, client, jobs, secfile, hostinfo
  /console/...         gateway, store (PostgreSQL), audit
  /e2e                 test end-to-end gateway ↔ agente
/modules               moduli funzionali e SDK (powershell, sh)
/packaging
  /wix                 MSI per Windows
  /linux               unit systemd, deb / rpm
/docs
```

Codice, identificatori e commenti sono in inglese (progetto open source); la documentazione è in italiano.

---

## 3. Modularità (R10) — il cuore del progetto

### 3.1 Cosa contiene il core e cosa no

**Nel core (cambia raramente):**
- connessione alla console, riconnessione, backoff, proxy
- identità dell'agente (certificato, rotazione)
- verifica delle firme di moduli e job
- download, cache e versionamento dei moduli
- esecuzione dei moduli come sottoprocessi, con timeout, limiti di output e kill
- scheduler locale delle policy (es. "scansione aggiornamenti ogni 6 ore")
- coda locale dei risultati quando la console non è raggiungibile

**Fuori dal core (moduli):** *tutto il resto*, incluso l'esecuzione PowerShell.

### 3.2 Tipi di modulo

| Tipo | Quando usarlo | Esempi |
|---|---|---|
| **Modulo PowerShell firmato** | La maggior parte delle funzionalità Windows: sviluppo rapido, accesso diretto a COM/WMI/registro | Inventario, log di accesso, Windows Update (API WUA via COM), winget (Microsoft.WinGet.Client), BitLocker |
| **Modulo binario Go firmato** | Prestazioni, parsing complesso, multipiattaforma, logica che non deve dipendere da PowerShell | Firmware (cataloghi Dell/Lenovo), Linux, raccolte pesanti di eventi |
| *(futuro)* Modulo WebAssembly | Sandbox forte per moduli di terze parti | — |

### 3.3 Manifest di modulo

Ogni modulo è un archivio zip con un manifest firmato (Ed25519, chiave di rilascio moduli offline). Il manifest indica l'entrypoint per ogni piattaforma, le azioni con i loro timeout, le capability, e lo SHA-256 dell'archivio e di ogni file. Il job contiene lo SHA-256 del manifest firmato, quindi l'agente esegue esattamente la versione approvata.

Formato completo, controlli e flusso di firma in [MODULI.md](MODULI.md).

### 3.4 Protocollo core ↔ modulo

- Il core avvia il modulo come sottoprocesso in una cartella di lavoro temporanea, con ambiente minimo, e gli scrive su stdin una riga JSON con azione e parametri.
- Il modulo risponde con righe JSON su stdout: `progress`, `log` e un solo evento finale `result` o `error`. Il core inoltra l'avanzamento alla console in tempo reale.
- Limiti di dimensione e timeout; in caso di violazione il core termina l'intero albero di processi (process group su Linux, Job Object su Windows).
- Gli SDK (`modules/sdk/powershell`, `modules/sdk/sh`) nascondono il protocollo a chi scrive i moduli.

### 3.5 Ciclo di vita di una nuova funzionalità

1. Si sviluppa il modulo (PowerShell o Go) e i suoi schemi.
2. Lo si firma con la **chiave di rilascio moduli** (offline, §6.3).
3. Lo si pubblica in console e lo si assegna a un anello (pilota → tutti).
4. Gli agenti lo scaricano alla prima richiesta, verificano firma e hash, lo mettono in cache.

**Nessun aggiornamento dell'agente.** L'agente va aggiornato solo se cambia il protocollo core↔modulo (`min_core_version`) o per correzioni di sicurezza del core.

### 3.6 Job

Ogni attività è un **job**: `{job_id, tenant_id, agent_id, module, version, module_sha256, action, params, not_before, scadenza, nonce}`, firmato.
- Job **immediati**: messi in coda nel database; il gateway li consegna sullo stream aperto dall'agente appena è connesso e approvato, risvegliato da una notifica PostgreSQL (`LISTEN/NOTIFY`), con un controllo di riserva a ogni heartbeat.
- Gli aggiornamenti finali (riuscito, fallito, rifiutato) vengono scritti dall'agente in una outbox su disco prima dell'invio e rispediti dopo disconnessioni o riavvii, finché la console non li conferma.
- Un job già ricevuto e consegnato di nuovo dopo una riconnessione non viene rieseguito: l'agente rimanda lo stato che conosce.
- Job **schedulati** (da fare): fanno parte della *policy* dell'agente, salvata in locale ed eseguita anche offline; i risultati vengono accodati.

---

## 4. Comunicazione agente ↔ console

- **gRPC su HTTP/2 con mTLS**, porta 443, stream bidirezionale **aperto dall'agente**.
- Heartbeat ogni 60 secondi. Con 200 endpoint il carico è trascurabile.
- Supporto proxy HTTP(S) (CONNECT) e lettura delle impostazioni proxy di sistema.
- Riconnessione con backoff esponenziale + jitter.
- Grandi trasferimenti (moduli, pacchetti) via HTTPS separato da `openrmm-repo`, sempre con verifica dell'hash firmato.

### 4.0 Regola: la console non contatta mai gli endpoint

- I comandi immediati viaggiano sullo stream **già aperto dall'agente**. Se l'agente non è connesso, il job resta in coda in console fino alla riconnessione, entro la sua scadenza.
- Se serve una reazione rapida a un PC appena acceso, l'agente si connette subito all'avvio del servizio e la coda viene consegnata in pochi secondi.
- **Wake-on-LAN** (futuro): il pacchetto di risveglio viene inviato da un altro agente acceso nella stessa subnet, su incarico della console. La console non invia nulla direttamente.
- La console è ospitata presso il cliente ed è **raggiungibile da internet**: i portatili fuori sede si collegano direttamente, senza VPN. Come viene esposta è descritto in §6.7.
- Gli agenti usano un nome DNS unico (es. `agent.cliente.it`) che risolve sia dalla LAN sia da internet, così il PC non deve sapere dove si trova.
- **Fuori sede**, i download pesanti non passano dalla console: aggiornamenti Windows da Microsoft, pacchetti winget e firmware dai siti dei produttori. La console fornisce solo i metadati firmati (hash) per verificarli. Il peer-to-peer (Delivery Optimization) resta limitato alla LAN.
- Lo stesso principio vale per la federazione (§9): è la console del cliente che si collega alla master, mai il contrario.

### 4.1 Enrollment

1. L'MSI riceve `SERVER_URL` e `ENROLL_TOKEN` (via MST o chiave di registro distribuita da GPO).
2. L'agente genera **in locale** la coppia di chiavi (protetta con TPM se disponibile, altrimenti DPAPI-machine).
3. Invia una CSR con il token. La console verifica il token (monouso o con limite d'uso e scadenza, legato a un tenant).
4. La console rilascia un certificato client con `agent_id` e `tenant_id`.
5. Il nuovo agente è **in attesa di approvazione** (`pending`), salvo che il token sia stato creato con approvazione automatica. Un agente in attesa può connettersi ed è visibile in console, ma non riceve job.
6. Rinnovo automatico del certificato (validità 90 giorni) quando ne resta meno di un terzo: l'agente genera una nuova chiave e chiede un nuovo certificato sulla connessione autenticata. Il certificato precedente resta valido finché l'agente non si collega con quello nuovo; i rinnovi di un certificato emesso da meno di un'ora sono rifiutati.
7. Revoca dalla console: l'agente viene disconnesso anche se è collegato in quel momento.
8. L'agente fa **pinning della CA della console** ricevuta all'installazione.

---

## 5. Resilienza e aggiornamento dell'agente

### 5.1 Ripartenza (R4)

| Livello | Windows | Linux |
|---|---|---|
| 1 | Service Recovery (`sc failure`: riavvio a 1ª/2ª/successive) | systemd `Restart=always` |
| 2 | `openrmm-watchdog` controlla salute (non solo "processo vivo" ma "risponde e comunica") | `WatchdogSec` + `openrmm-watchdog` |
| 3 | Task schedulato ogni 15 min: verifica che entrambi i servizi esistano e siano avviati, altrimenti li ripristina | timer systemd |

### 5.2 Aggiornamento dell'agente (R11)

- Pacchetti dell'agente firmati con la **chiave di rilascio agente** (offline), metadati secondo il modello **TUF** (protezione da rollback a versioni vecchie e da metadati congelati).
- Installazione **A/B**: la nuova versione va in una cartella separata. Il watchdog la avvia e, se entro N minuti non raggiunge lo stato "sano" (connessa alla console), torna alla versione precedente e segnala l'errore.
- Rollout per **anelli** (pilota → 25% → tutti), con pausa automatica se la percentuale di fallimenti supera una soglia.
- Il watchdog si aggiorna con lo stesso meccanismo, ma tramite l'agente (si aggiornano a vicenda, mai entrambi insieme).

---

## 6. Sicurezza

### 6.1 Modello delle minacce (sintesi)

| Minaccia | Mitigazione |
|---|---|
| Console compromessa usata per eseguire codice su tutti gli endpoint | Firma separata di moduli e job (§6.3), policy locali non modificabili dalla console (§6.4), approvazioni a 4 occhi |
| Agente falso che si registra | Token di enrollment monouso, legato al tenant, con scadenza |
| Man-in-the-middle | mTLS + pinning della CA |
| Manipolazione locale dell'agente | ACL su cartelle, chiavi e named pipe; binari firmati Authenticode; verifica dell'integrità all'avvio |
| Modulo o pacchetto manomesso | Firma ed25519 + hash, verificati **prima** dell'esecuzione |
| Replay di un job | `nonce` + scadenza + `agent_id` nel payload firmato |
| Abuso da parte di un operatore | RBAC, MFA, audit log non modificabile, limiti per numero di endpoint |
| Supply-chain nelle dipendenze | Dipendenze minime, `govulncheck`, SBOM, build riproducibili |

### 6.2 Chiavi

| Chiave | Dove | Firma |
|---|---|---|
| Rilascio agente | Offline (HSM o chiavetta, es. YubiKey) | Pacchetti agente/watchdog |
| Rilascio moduli | Offline | Moduli |
| Firma job | `openrmm-signer`, processo isolato (in futuro HSM) | Ogni job inviato agli agenti |
| CA agenti | Console (offline per la root, intermedia online) | Certificati client degli agenti |
| Authenticode | Fornitore di code signing | Binari ed MSI Windows |

### 6.3 Firma dei job

- Nessun job viene eseguito se non è firmato da `openrmm-signer`.
- `openrmm-signer` firma solo dopo aver ricontrollato in modo indipendente RBAC, **la prova MFA legata a quel job** (§6.6) e le approvazioni richieste. Così una vulnerabilità nell'API principale non basta a far firmare un job.
- Il job firmato contiene l'hash del modulo da eseguire: si possono eseguire solo moduli firmati con la chiave di rilascio offline.

### 6.4 Policy locali dell'agente

Impostate all'installazione (proprietà MSI / GPO), **modificabili solo da un amministratore locale o via GPO, mai dalla console**:

- `AllowAdHocScripts` (default: **1**, attivo su client e server; disattivabile via GPO su singoli gruppi di macchine)
- `AllowUserContextExecution`
- `MaxConcurrentJobs`
- Lista dei tenant / console autorizzati

Anche con la console compromessa, un endpoint con `AllowAdHocScripts=0` non esegue PowerShell arbitrario.

### 6.5 Sviluppo sicuro

- Go con `go vet`, `staticcheck`, `gosec`, `govulncheck` in CI.
- Fuzzing dei parser (protocollo, manifest, cataloghi firmware).
- Nessun segreto nei log. Le password del BIOS e simili sono cifrate e passate al modulo solo in memoria.
- Revisione obbligatoria del codice su core, signer e verifica firme.

### 6.6 Autenticazione degli operatori (R12)

Accesso **solo con account Microsoft 365 (Entra ID)**, con nome utente e password sulla pagina di accesso di Microsoft. **Non esistono account locali della console**, salvo un account di emergenza (sotto). L'AD on-prem del cliente non è sincronizzato con Entra e non viene usato per l'accesso alla console. Gli agenti continuano a gestire normalmente i PC a dominio: autenticazione degli operatori e gestione degli endpoint sono indipendenti.

- **Protocollo:** OIDC, authorization code + PKCE. La console non vede mai la password dell'operatore.
- **Registrazione:** un'app registration nel tenant Entra del cliente; accesso consentito solo agli utenti assegnati all'applicazione.
- **MFA:** applicata da Entra. La console **rifiuta il login** se il token non attesta l'MFA (claim `amr`).
  - Con Entra ID P1 (incluso in Microsoft 365 Business Premium / E3 / E5): una policy di **Conditional Access** dedicata alla console, con *authentication strength* resistente al phishing (FIDO2, Windows Hello for Business, passkey in Microsoft Authenticator) e, se si vuole, dispositivo conforme o posizione.
  - Senza P1: *security defaults* di Entra, che impongono l'MFA con Microsoft Authenticator.
- **Ruoli:** app role di Entra (es. `Admin`, `Tecnico`, `SolaLettura`) assegnati a gruppi Entra → ruoli della console.
- **Revoca:** disabilitando l'utente in Entra si perde l'accesso alla console al rinnovo successivo del token (durata breve).

**MFA prima dell'esecuzione di comandi**
- Ogni esecuzione di PowerShell avviata a mano da un operatore richiede una **nuova autenticazione con MFA in quel momento**, anche se l'operatore è già dentro la console: la console richiede a Entra `prompt=login` e `max_age=0` e verifica `auth_time` e `amr` nel token.
- La verifica è **legata al job specifico**: il `nonce` della richiesta di autenticazione contiene l'hash di script, parametri ed endpoint di destinazione.
- `openrmm-signer` controlla questa prova prima di firmare. Una sessione rubata, senza il secondo fattore, non basta per eseguire comandi.
- Le attività schedulate nelle policy non richiedono MFA a ogni esecuzione: l'MFA viene richiesta quando la policy viene creata o modificata.

**Sessioni**
- Cookie `HttpOnly`, `Secure`, `SameSite=Strict`, protezione CSRF, durata breve e scadenza per inattività.
- Ogni login, riuscito o fallito, finisce nell'audit; vengono registrati anche i log di accesso Entra all'applicazione.

**Account di emergenza (break-glass)**: un solo account locale, solo con chiave FIDO2 conservata in cassaforte, per quando Entra non è raggiungibile. Utilizzabile **solo dalla LAN**. Ogni suo utilizzo genera un alert.

### 6.7 Esposizione su internet (R13)

Esporre su internet la console di un RMM la rende un bersaglio. Per questo **l'endpoint degli agenti e l'interfaccia web sono separati**:

```
                       internet
                          │
              ┌───────────┴────────────┐
              │  firewall / DMZ        │
              │                        │
   agent.cliente.it:443        console.cliente.it:443
   (TLS passthrough, mTLS)     (reverse proxy + WAF,
              │                 accesso ristretto)
              ▼                        ▼
       openrmm-gateway  ──────►  openrmm-server ──► PostgreSQL
                                 (rete interna, mai esposto)
```

**Endpoint degli agenti (`agent.cliente.it`)**
- Il TLS viene terminato **direttamente da `openrmm-gateway`** (passthrough sul firewall/proxy), così è il gateway a verificare il certificato client.
- **Senza un certificato client valido non si raggiunge nessuna logica applicativa**: chi non è un agente vede solo un handshake TLS fallito.
- Unica eccezione: l'endpoint di **enrollment**, che accetta il token di enrollment. È fortemente limitato (rate limiting per IP, token con scadenza e numero massimo di utilizzi, token revocabili, alert sugli enrollment).
- Certificato server emesso dalla **CA privata di open-rmm**, che gli agenti hanno in pinning. Non dipende da CA pubbliche. Le reti che ispezionano il TLS (alcuni hotel e reti aziendali di terzi) bloccheranno la connessione: è voluto, e l'agente riprova quando cambia rete.
- Limiti di connessioni e richieste per agente; disconnessione degli agenti revocati.

**Interfaccia web (`console.cliente.it`)**
- Consigliato: **non esporla su internet** e renderla raggiungibile solo da LAN o VPN degli operatori.
- Se deve essere raggiungibile da fuori: dietro **Entra Application Proxy** (l'utente si autentica su Entra prima ancora di raggiungere la console, e la Conditional Access si applica anche qui), oppure dietro reverse proxy con WAF e lista di IP consentiti.
- Header di sicurezza (HSTS, CSP restrittiva, `X-Frame-Options`), certificato pubblico valido.

**Server della console**
- In DMZ o in una rete dedicata. PostgreSQL e `openrmm-signer` non sono mai raggiungibili dall'esterno.
- Aggiornamenti della console stessa (sistema operativo, container) pianificati e monitorati.
- Log del gateway e della console inviati, se disponibile, al SIEM del cliente.
- Backup cifrati del database, con prova periodica di ripristino.

---

## 7. Esecuzione di comandi PowerShell (R9)

È la funzionalità più potente e più pericolosa. Viene implementata come **modulo** (`script`), non nel core.

### 7.1 Due modalità

| Modalità | Uso | Controlli |
|---|---|---|
| **Libreria di script** | Script riutilizzabili, versionati in console | Revisione e approvazione di un secondo operatore prima della pubblicazione; parametri tipizzati; MFA prima di ogni esecuzione manuale |
| **Comando ad hoc** | Diagnostica veloce su un PC | Attivo di default (`AllowAdHocScripts=1`); permesso RBAC dedicato; **MFA richiesta prima di ogni esecuzione** e legata al comando (§6.6); limite di endpoint per esecuzione (es. max 5 senza approvazione) |

### 7.2 Esecuzione sull'endpoint

- `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass`, oppure PowerShell 7 se presente e richiesto.
- Lo script viene passato **tramite stdin o file temporaneo con ACL ristrette**, mai sulla riga di comando (visibile nell'elenco processi e nei log).
- Contesto: SYSTEM (default) oppure utente connesso, tramite `openrmm-userhelper`.
- Timeout, limite dimensione output, terminazione dell'intero albero di processi.
- Output (stdout, stderr, exit code) in streaming verso la console.
- **Non si disattivano** Script Block Logging, AMSI o Defender: sono controlli utili anche per noi.

### 7.3 Audit

Per ogni esecuzione: operatore, approvatore, testo integrale dello script (hash e contenuto), endpoint, orario, output, exit code. Il log è append-only, con catena di hash per renderlo verificabile.

### 7.4 Futuro

Shell interattiva remota (sessione PowerShell in tempo reale), con le stesse regole delle esecuzioni ad hoc e registrazione della sessione.

---

## 8. Moduli funzionali

### 8.1 `inventory`

Due azioni separate, `hardware` e `software`, con frequenze diverse.

#### Inventario hardware

| Area | Dati raccolti | Fonte su Windows |
|---|---|---|
| Sistema | Produttore, modello, SKU/codice modello, numero di serie, tipo di chassis (desktop, portatile, server, VM), hypervisor se virtuale | `Win32_ComputerSystem`, `Win32_ComputerSystemProduct`, `Win32_SystemEnclosure` |
| BIOS/UEFI | Versione, data di rilascio, modalità UEFI/legacy, stato Secure Boot, **certificati Secure Boot 2023 presenti o no**, voci ESRT | `Win32_BIOS`, registro `SecureBoot`, `HKLM\HARDWARE\UEFI\ESRT` |
| CPU | Modello, core e thread, frequenza, architettura | `Win32_Processor` |
| Memoria | Totale e **dettaglio per banco**: capacità, velocità, produttore, numero di serie, slot liberi | `Win32_PhysicalMemory`, `Win32_PhysicalMemoryArray` |
| Dischi fisici | Modello, numero di serie, capacità, tipo (SSD/HDD/NVMe), **stato di salute**, usura, temperatura, ore di funzionamento | `MSFT_PhysicalDisk`, `Get-StorageReliabilityCounter` |
| Volumi | Lettera, file system, spazio totale e libero, **stato BitLocker** e protettori | `Win32_Volume`, `Win32_EncryptableVolume` |
| Rete | Schede (fisiche e virtuali), MAC, IP, gateway, DNS, velocità, versione del driver, Wi-Fi/cablata | `MSFT_NetAdapter`, `Get-NetIPConfiguration` |
| Video e monitor | Scheda video e driver; monitor collegati con produttore, modello e **numero di serie** | `Win32_VideoController`, `WmiMonitorID` |
| Batteria (portatili) | Capacità di progetto e capacità attuale → **salute della batteria in %**, cicli | `BatteryStaticData`, `BatteryFullChargedCapacity` |
| TPM | Presenza, versione, stato (attivo/proprietà) | `Win32_Tpm` |
| Sistema operativo | Edizione, versione e build, data di installazione, stato di attivazione, ultimo avvio | `Win32_OperatingSystem`, registro |

**Invio e storico**
- Inventario completo all'enrollment, poi **ogni 24 ore** e a ogni avvio del servizio.
- L'agente invia solo le **differenze** rispetto all'ultimo invio, con un hash dell'inventario completo per riallinearsi se necessario.
- La console conserva lo **storico delle modifiche**: RAM o dischi rimossi o sostituiti, monitor scambiati, cambio di numero di serie. Le modifiche possono generare alert (per esempio un banco di RAM sparito, o la salute di un disco in calo).
- Report: età del parco (data del BIOS), dischi a rischio, batterie degradate, PC sotto i requisiti minimi (RAM, TPM 2.0, CPU per Windows 11).
- Futuro: stato della garanzia tramite le API di Dell e Lenovo.
- Linux (fase 4): `dmidecode`, `lsblk`, `smartctl`, `/sys/class/power_supply`.

#### Inventario software
- Chiavi `Uninstall` (32/64 bit, HKLM e HKCU per ogni profilo) e app MSIX. **Mai `Win32_Product`.**
- Correlazione con gli ID winget: *aggiornabile / aggiornato / non gestibile*.
- Invio a ogni modifica rilevata e comunque ogni 24 ore, sempre come differenze.

### 8.2 `winupdate`
- API WUA via COM: `scan`, `download`, `install`, `history`.
- Sorgente: Microsoft Update o WSUS. Rilevamento della configurazione di Windows Update e dei **conflitti con le GPO**.
- Policy: categorie (sicurezza e critici automatici dopo N giorni, Defender sempre, driver esclusi, feature update manuali), anelli, blocco di singoli KB, finestre di manutenzione.
- Riavvii: il modulo segnala *riavvio necessario*; il riavvio vero e proprio lo gestisce il modulo `reboot` secondo la policy del gruppo (§8.6).
- Errori: traduzione dei codici `0x8024xxxx`, retry, modulo di rimedio separato (`wu-repair`: reset dei componenti, DISM, sfc).

**Coesistenza con WSUS e Intune (R14).** Oggi il cliente non sembra usarli, ma il modulo li rileva sempre e lavora in una di due modalità per gruppo di endpoint:

| Modalità | Quando | Comportamento |
|---|---|---|
| **Gestita** | Nessun altro sistema decide sugli aggiornamenti (situazione attuale) | L'RMM decide cosa installare e quando |
| **Osservazione** | Gli aggiornamenti li gestisce WSUS o Intune | L'RMM non installa nulla. Fa solo scansione e report di conformità, rilevazione dei riavvii in sospeso ed eventuale rimedio degli errori |

- **Rilevamento WSUS:** chiavi di policy `WUServer` / `UseWUServer`. Con WSUS attivo la scansione vede solo gli aggiornamenti approvati su WSUS; il report lo indica chiaramente.
- **Rilevamento Intune / Windows Update for Business:** iscrizione MDM, policy di update ring (`PolicyManager\current\device\Update`), co-management con ConfigMgr.
- **Conflitto rilevato:** se su un PC in modalità *gestita* compaiono policy WSUS o Intune, la console mostra un avviso e il PC passa in *osservazione* finché un operatore non decide.
- Passaggio da WSUS/Intune all'RMM: documentiamo quali policy rimuovere o modificare.

### 8.3 `accesslog` — login locali e RDP (priorità alta)
- **Raccolta sull'endpoint**, eventi normalizzati (utente, dominio, tipo di accesso, IP e nome del client, esito, motivo del fallimento):
  - accessi riusciti `4624` per tipo: 2 interattivo, 7 sblocco, 10 RemoteInteractive (RDP), 11 credenziali in cache, 3 rete (filtrato);
  - accessi falliti `4625`, logoff `4634`/`4647`, privilegi speciali `4672`, account bloccato `4740`;
  - RDP: `1149` (TerminalServices-RemoteConnectionManager, con IP sorgente), `21`/`24`/`25` (LocalSessionManager: accesso, disconnessione, riconnessione).
- Raccolta incrementale (segnalibro sull'ultimo record letto), così niente duplicati né buchi dopo un riavvio.
- In console vanno solo gli eventi filtrati e normalizzati, non i log grezzi (volume e GDPR).
- **Rilevamento dei login inusuali in console**, che vede lo storico di tutti gli endpoint:
  - per ogni coppia utente/endpoint si costruisce una "normalità" fatta di IP sorgenti RDP (e relative subnet /24), orari e giorni abituali, client;
  - alert per un accesso RDP da un IP o una subnet mai visti per quell'utente o quell'endpoint, da IP pubblico verso un server, fuori dai propri orari, con privilegi amministrativi;
  - alert per tentativi falliti ripetuti, anche distribuiti su più utenti (password spraying);
  - un periodo di apprendimento iniziale evita falsi allarmi a raffica; un operatore può marcare un IP o una subnet come attesi.
- Serve l'esecuzione periodica dei moduli tramite policy (job schedulati, §3.6), da implementare prima di questo modulo.

### 8.3.1 Trend Micro (priorità alta)
- **`trendmicro-visionone`**: stato dell'agente Trend Vision One sull'endpoint.
  - Installato o no, versione, servizi in esecuzione.
  - Connessione al cloud Vision One.
  - Componenti (pattern, motore) e data dell'ultimo aggiornamento.
  - Protezione in tempo reale attiva.
  - Alert se l'agente manca, è fermo o non è aggiornato.
- **`trendmicro-ztsa`**: stato del client Zero Trust Secure Access: installato, versione, servizio attivo, connesso.
- Da chiarire: i dettagli dipendono dalla versione dell'agente Trend installata. In alternativa, o in aggiunta, la console può interrogare le API di Vision One per avere la vista lato cloud.

### 8.4 `winget`
- Uso tramite **Microsoft.WinGet.Client / API COM**, non tramite parsing dell'output testuale.
- `bootstrap`: installa o aggiorna App Installer dove manca (server, LTSC), verificandone la firma.
- Solo **pacchetti presenti nella lista approvata** della console; anelli; blocco delle versioni.
- App per-utente aggiornate in contesto utente tramite `openrmm-userhelper`.
- Gestione del caso "tecnologia di installazione diversa": disinstalla e reinstalla solo con approvazione.
- Futuro: sorgente REST privata per pacchetti interni e versioni validate.

### 8.5 `firmware-*`
- `firmware-dell` (Dell Command | Update), `firmware-lenovo` (Thin Installer), altre marche tramite la categoria Firmware di Windows Update.
- Prerequisiti verificati dal modulo: alimentazione collegata, batteria sopra soglia, **chiave BitLocker salvata in AD o Entra ID**, poi **sospensione di BitLocker per un riavvio**.
- Firma e hash degli strumenti del produttore verificati prima dell'esecuzione; cataloghi scaricati e verificati dalla console, che fa da cache.
- Mai automatico di default; anelli per modello; verifica della versione dopo il riavvio.
- Il riavvio passa dal modulo `reboot` (§8.6), con avviso all'utente che il riavvio sarà più lungo del solito.

### 8.6 `reboot` — riavvii configurabili (R15)

Qualunque modulo che richiede un riavvio (Windows Update, firmware, winget, script) **non riavvia da solo**: segnala *riavvio necessario* con il motivo. Il modulo `reboot` lo esegue secondo la **policy di riavvio** assegnata al gruppo di endpoint, con possibile eccezione sul singolo PC.

**Parametri della policy**

| Parametro | Valori | Esempio client | Esempio server |
|---|---|---|---|
| Modalità | `mai` (solo notifica e report) · `notifica con rinvii` · `solo in finestra di manutenzione` · `immediato con preavviso` | notifica con rinvii | solo in finestra |
| Finestra di manutenzione | giorni e fascia oraria | — | dom 02:00–05:00 |
| Rinvii consentiti all'utente | numero massimo e durate proposte | 3 rinvii: 1 h, 4 h, domani | — |
| Scadenza | ore o giorni dopo l'installazione | 72 h | — |
| Comportamento alla scadenza | riavvio forzato con conto alla rovescia · solo notifica insistente | forzato, preavviso 15 min | — |
| Nessun utente connesso | riavvia subito · attendi la finestra | riavvia subito | attendi la finestra |
| Orari di non disturbo | fasce in cui non si riavvia mai | 08:30–13:00 | — |
| Non disturbare durante presentazioni | sì / no (schermo intero, modalità presentazione) | sì | — |
| Portatili | non riavviare a batteria sotto una soglia | 30% | — |
| Testo del messaggio | personalizzabile, multilingua | testo del cliente | — |
| Script pre/post riavvio | script firmati dalla libreria | — | stop servizio applicativo |

**Funzionamento**
- Le notifiche e i rinvii passano da `openrmm-userhelper` nella sessione dell'utente.
- Il riavvio in sospeso viene rilevato anche se causato da fuori dall'RMM (CBS, Windows Update, `PendingFileRenameOperations`).
- Dalla console: riavvio manuale di un PC o di un gruppo (con MFA, come i comandi), stato dei riavvii in sospeso, storico.
- Più richieste di riavvio insieme vengono unite in un solo riavvio.
- Dopo il riavvio, i moduli che lo avevano richiesto verificano l'esito e lo riportano in console.

---

## 9. Multi-tenancy e federazione

- `tenant_id` in ogni tabella, API e job; isolamento con PostgreSQL RLS.
- Una sola console può gestire **tenant locali** (agenti collegati direttamente) e **tenant federati** (altre console collegate sotto di lei).
- Il collegamento federato è avviato dalla console figlia, con mTLS. La figlia decide cosa condividere e quali azioni delegare, e può staccarsi in qualunque momento.
- Ai riepiloghi sincronizzati si aggiungono i dettagli richiesti al momento. La figlia resta pienamente autonoma.
- Identità dell'operatore propagata nell'audit della figlia. La firma dei job resta sempre sulla console che gestisce l'agente.
- Al massimo due livelli (master → console clienti).

---

## 10. Packaging e installazione

- **MSI** costruito su Linux con msitools/wixl, che usa lo schema WiX v3 ed è distribuito con licenza LGPL. Proprietà: `SERVER`, `ENROLLTOKEN`, `ROOTCA`, `JOBSIGNINGKEYS`, `MODULESIGNINGKEYS`, `RELEASESIGNINGKEYS`, `ALLOWADHOCSCRIPTS`. Dettagli in [INSTALLAZIONE-AGENTE.md](INSTALLAZIONE-AGENTE.md).
- Con la GPO l'MSI si assegna così com'è e la configurazione arriva dal modello **ADMX** (`HKLM\SOFTWARE\Policies\open-rmm`), senza file MST.
- L'MSI installa i file e i servizi `openrmm-agent` e `openrmm-watchdog`. Le impostazioni che wixl non esprime vengono applicate dai servizi stessi a ogni avvio:
  - azioni di ripristino e avvio ritardato;
  - task schedulato di controllo;
  - ACL del registro e di `C:\ProgramData\open-rmm`.
- Senza configurazione completa i servizi restano avviati e la riprovano ogni minuto, così un'installazione fatta prima dei criteri non fallisce.
- I servizi sono registrati con `-service`: la modalità servizio è esplicita, non dedotta.
- Disinstallazione protetta: richiede un codice o un comando dalla console, per evitare rimozioni da parte di malware o utenti.
- Linux (fase 4): pacchetti `.deb`/`.rpm` con unit systemd.

---

## 11. Roadmap

| Fase | Contenuto | Risultato |
|---|---|---|
| **0 — Fondamenta** | Gateway esposto con mTLS e separazione dall'interfaccia web, login Entra ID, PKI ed enrollment, core agente, watchdog, task schedulato, protocollo gRPC, module manager + SDK PowerShell, `openrmm-signer`, console di base (login MFA, tenant, elenco endpoint, audit), MSI | Agente installabile via GPO che si registra e resta connesso |
| **1 — MVP** | `inventory` (hardware e software), `script` (libreria + ad hoc), `winupdate` (scansione, installazione, policy, finestre di manutenzione), `accesslog`, aggiornamento automatico dell'agente | Il cliente usa l'RMM per patch e diagnostica |
| **2** | `openrmm-userhelper` con notifiche, modulo `reboot` con policy configurabili, anelli, `winget` + bootstrap, report di conformità | Patch dei client senza disturbare gli utenti, software di terze parti aggiornato |
| **2b** | Job schedulati via policy, `accesslog` con rilevamento dei login inusuali, `trendmicro-visionone`, `trendmicro-ztsa` | Sicurezza degli endpoint visibile in console |
| **3** | `firmware-dell`, `firmware-lenovo`, firmware via Windows Update, controlli BitLocker, `wu-repair` | Firmware gestito |
| **4** | Agente Linux (pacchetti, fwupd, log, aggiornamenti apt/dnf), federazione in sola lettura | Copertura Linux, vista multi-cliente |
| **5** | Comandi dalla master con deleghe, sorgente winget privata, Redfish per i server, shell interattiva | — |

---

## 12. Decisioni aperte

1. Il cliente ha Entra ID P1 (Business Premium / E3 / E5)? Determina se si può usare la Conditional Access per la console.
2. L'interfaccia web della console deve essere raggiungibile da internet, o basta LAN/VPN per gli operatori?
3. Mappatura gruppi Entra → ruoli della console (amministratore, tecnico, sola lettura).
4. Valori predefiniti delle policy di riavvio per client e server (proposta in §8.6).
5. Fornitore del certificato Authenticode e gestione delle chiavi offline (YubiKey/HSM).

## 13. Decisioni prese

| Data | Decisione |
|---|---|
| 2026-10-16 | Nome del progetto: **open-rmm** |
| 2026-10-16 | Agente e backend della console in **Go**, database **PostgreSQL** |
| 2026-10-16 | Primo cliente: ~200 endpoint |
| 2026-10-16 | Accesso alla console **solo con utenti Microsoft 365 (Entra ID)**, **MFA obbligatoria**. AD on-prem non usato (non sincronizzato con Entra) |
| 2026-10-16 | Comandi PowerShell ad hoc **attivi di default**, con **MFA richiesta prima di ogni esecuzione** |
| 2026-10-16 | Console **ospitata presso il cliente**; tutte le comunicazioni partono dagli endpoint |
| 2026-10-16 | WSUS e Intune oggi non presenti, ma supportati in modalità *osservazione* |
| 2026-10-16 | Inventario hardware completo inviato dall'agente |
| 2026-10-16 | Portatili anche fuori sede; console raggiungibile da internet, con endpoint agenti separato dall'interfaccia web |
| 2026-10-16 | Riavvii configurabili tramite policy per gruppo |
| 2026-10-16 | Codice e commenti in inglese, documentazione in italiano |
| 2026-10-16 | La console rifiuta di avviarsi con un ruolo PostgreSQL superuser o BYPASSRLS (la RLS verrebbe ignorata) |
| 2026-10-17 | Il server della console gira in **container Linux** (Docker Compose): solo il gateway è esposto, PostgreSQL su rete interna |
| 2026-10-17 | **Nuovi agenti in attesa di approvazione** per default; l'**approvazione automatica** è un'opzione del singolo token di enrollment |
| 2026-10-17 | **Rinnovo automatico** del certificato dell'agente a 2/3 della validità, con nuova chiave; il certificato precedente resta valido fino al primo uso del nuovo |
| 2026-10-17 | Moduli eseguiti come sottoprocessi con protocollo JSON a righe; il job fissa l'hash del manifest; esecuzione in contesto utente rimandata a `openrmm-userhelper` |
| 2026-10-17 | Interfaccia web generata dal server invece di React: nessuna dipendenza JavaScript, CSP restrittiva, superficie d'attacco minima |
| 2026-10-17 | Firma dei job in `openrmm-signer` (container separato, socket locale): firma solo con un id_token Entra fresco, con MFA, il cui `nonce` è l'impronta esatta del comando |
| 2026-10-17 | Aggiornamento dell'agente: release firmate con chiave dedicata, versioni affiancate, switch e rollback del watchdog, mai downgrade, rollout per anelli |
| 2026-10-17 | Moduli prioritari: stato Trend Micro Vision One e ZTSA, login locali/RDP con rilevamento dei login inusuali |
| 2026-10-17 | MSI costruito con msitools/wixl (LGPL, su Linux) invece di WiX Toolset; configurazione via ADMX per la GPO |
