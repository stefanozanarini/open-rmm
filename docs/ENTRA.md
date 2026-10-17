# Configurazione di Microsoft Entra ID

La console usa Entra ID (Microsoft 365) per il login degli operatori e per approvare ogni singolo comando. Tutto si configura nel [centro di amministrazione Entra](https://entra.microsoft.com) del cliente, con un account Amministratore applicazioni o superiore.

> **Da verificare sul tenant reale.** Il flusso è stato provato con un identity provider OIDC di test e la discovery con i server Microsoft funziona, ma non è ancora stato provato un login vero su un tenant Entra. Al primo login controlla i log del server (`docker compose logs server`): se l'accesso viene rifiutato per l'MFA, il messaggio riporta i valori ricevuti di `amr` e `acrs`.

## 1. Registrazione dell'applicazione

**Identità → Applicazioni → Registrazioni app → Nuova registrazione**

| Campo | Valore |
|---|---|
| Nome | `open-rmm console` |
| Tipi di account supportati | Solo gli account in questa directory organizzativa |
| URI di reindirizzamento | Piattaforma **Web**: `https://console.cliente.it/auth/callback` (lo stesso host di `OPENRMM_PUBLIC_URL`) |

Annota **ID applicazione (client)** e **ID directory (tenant)** dalla pagina Panoramica.

## 2. Segreto client

**Certificati e segreti → Nuovo segreto client**, con scadenza di 12 mesi. Copia subito il **valore** in un file e usalo con `setup-secrets.sh`, che lo installa per il container. Prima della scadenza crea un nuovo segreto e ripeti l'operazione.

## 3. Ruoli dell'applicazione

**Ruoli app → Crea ruolo app**, tre volte (tipi di membri consentiti: *Utenti/Gruppi*):

| Nome visualizzato | Valore | Cosa permette |
|---|---|---|
| open-rmm Amministratore | `OpenRMM.Admin` | Tutto: approvare e revocare agenti, creare token, eseguire comandi |
| open-rmm Operatore | `OpenRMM.Operator` | Vedere tutto ed eseguire comandi |
| open-rmm Lettura | `OpenRMM.Reader` | Solo consultazione |

## 4. Chi può accedere

**Applicazioni aziendali → open-rmm console**:

- **Proprietà → Assegnazione utenti obbligatoria: Sì.** Senza questa impostazione qualunque utente della directory potrebbe tentare l'accesso (verrebbe comunque rifiutato dalla console se privo di ruolo).
- **Utenti e gruppi → Aggiungi assegnazione**: assegna i ruoli. Meglio assegnarli a gruppi dedicati (es. `open-rmm-admin`).

## 5. MFA

La console accetta il login e ogni comando solo se il token attesta l'MFA. Ci sono due modi.

### Con Entra ID P1 (consigliato)

Entra ID P1 è incluso in Microsoft 365 Business Premium, E3 ed E5. Con P1 l'MFA viene richiesta **a ogni comando**:

1. **Protezione → Accesso condizionale → Contesto di autenticazione → Nuovo**: nome `open-rmm comando`, ID `c1`, pubblicato nelle app.
2. **Nuovo criterio** "open-rmm: MFA per i comandi":
   - Utenti: gli operatori (o tutti).
   - Risorse di destinazione: **Contesto di autenticazione → `c1`**.
   - Concedi: **Richiedi livello di autenticazione** → *MFA resistente al phishing* (FIDO2, Windows Hello for Business, passkey), oppure almeno *Autenticazione a più fattori*.
   - Sessione: **Frequenza di accesso → Ogni volta**.
3. **Nuovo criterio** "open-rmm: accesso alla console": risorsa l'app *open-rmm console*, concedi *Richiedi autenticazione a più fattori*.
4. Nel file `.env`: `OPENRMM_MFA_CLAIM=acrs:c1`.

La console richiede il contesto `c1` sia al login sia per ogni comando, ed Entra lo riporta nel claim `acrs` del token solo se il criterio è stato soddisfatto.

### Senza P1

Con le *impostazioni predefinite per la sicurezza* di Entra l'MFA è obbligatoria, ma non si può imporre che venga richiesta di nuovo a ogni comando: Entra potrebbe considerare valida un'MFA fatta poco prima. La console chiede comunque una nuova autenticazione (`prompt=login`) per ogni comando.

Nel file `.env`: `OPENRMM_MFA_CLAIM=amr`. La console controlla che il claim `amr` contenga `mfa`. Questa modalità va verificata al primo login: se Entra non include `amr` nel token, il login viene rifiutato e il log lo indica.

## 6. Valori per il file .env

```bash
OPENRMM_OIDC_ISSUER=https://login.microsoftonline.com/<ID directory>/v2.0
OPENRMM_OIDC_CLIENT_ID=<ID applicazione>
OPENRMM_MFA_CLAIM=acrs:c1          # oppure amr
OPENRMM_TENANT_MAP=<ID directory>=<ID tenant open-rmm>
```

L'ID del tenant open-rmm è quello restituito da `openrmm-admin tenant create`. Con più tenant open-rmm gestiti dagli stessi operatori: `<ID directory>=<tenant1>|<tenant2>`.

## Cosa verifica il servizio di firma

Per ogni comando `openrmm-signer` controlla da solo, senza fidarsi della console:

- la firma del token, con le chiavi pubbliche scaricate da Microsoft;
- emittente, destinatario (l'ID applicazione) e scadenza;
- l'MFA, secondo `OPENRMM_MFA_CLAIM`;
- che l'autenticazione abbia al massimo 10 minuti;
- il ruolo `OpenRMM.Operator` o `OpenRMM.Admin`;
- che la directory dell'operatore possa gestire quel tenant;
- che il `nonce` del token sia l'impronta esatta del comando: agente, modulo, versione, azione, parametri, validità;
- che quel token non sia già stato usato.

Ogni comando firmato viene registrato anche nel log del signer, indipendente da quello della console.
