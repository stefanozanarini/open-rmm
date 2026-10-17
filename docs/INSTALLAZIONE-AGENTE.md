# Installazione dell'agente su Windows

L'agente si installa con un pacchetto MSI, adatto alla distribuzione tramite Criteri di gruppo (GPO). Il pacchetto installa l'agente e il watchdog come servizi di sistema; la configurazione arriva da GPO (consigliato) o dalle proprietà dell'MSI.

## Cosa serve

| Valore | Da dove si prende |
|---|---|
| Indirizzo della console | `agent.cliente.it:443` (l'endpoint degli agenti) |
| Certificato radice | `openrmm-admin pki root-b64 -in pki/ca/root-ca.crt` (una riga base64) |
| Token di registrazione | console → **Token**, oppure `openrmm-admin token create` |
| Chiave dei comandi | stampata da `setup-secrets.sh` (`ed25519:…`) |
| Chiave dei moduli | chiave pubblica di rilascio moduli (macchina offline) |
| Chiave delle release | chiave pubblica di rilascio dell'agente (macchina offline) |

## Costruire il pacchetto

```bash
make msi VERSION=1.0.0
# → dist/openrmm-agent-1.0.0-x64.msi
```

Il pacchetto si costruisce su Linux con msitools/wixl (in un container, o con `wixl` installato). La CI lo costruisce a ogni push e lo pubblica come artefatto.

> **Da fare prima della produzione:** firmare con Authenticode sia gli eseguibili sia l'MSI, con un certificato di firma del codice dell'azienda. Senza firma SmartScreen e alcuni antivirus potrebbero bloccarli; si può fare su Linux con `osslsigncode`.

## Distribuzione con Criteri di gruppo (consigliata)

1. **Modelli amministrativi.** Copia nel *Central Store* del dominio (`\\dominio\SYSVOL\dominio\Policies\PolicyDefinitions`):
   - `packaging/admx/open-rmm.admx`
   - `packaging/admx/it-IT/open-rmm.adml` nella sottocartella `it-IT` (e `en-US` se serve).
2. **Configurazione.** Nell'oggetto Criteri di gruppo dei computer: **Configurazione computer → Criteri → Modelli amministrativi → open-rmm**:
   - *Indirizzo della console*, *Token di registrazione*;
   - *Fiducia e chiavi*: certificato radice e le tre chiavi pubbliche;
   - *Policy locali*: script PowerShell ad hoc consentiti o no, comandi contemporanei.
3. **Installazione.** Copia l'MSI in una cartella di rete leggibile dai computer (es. `\\fileserver\deploy$\open-rmm\`), poi **Configurazione computer → Criteri → Impostazioni del software → Installazione software → Nuovo → Pacchetto → Assegnato**.

Al riavvio successivo i PC installano l'agente, che si registra e compare nella console **in attesa di approvazione**.

I valori dei Criteri di gruppo hanno la precedenza su quelli scritti dall'MSI e restano sotto il controllo del dominio. Se l'MSI viene installato prima che i criteri arrivino, i servizi restano avviati e riprovano a leggere la configurazione ogni minuto.

**Il token nei Criteri di gruppo è leggibile da tutti gli utenti del PC.** Per questo:

- usa un token **senza approvazione automatica** e con un numero di utilizzi vicino al numero di PC;
- dagli una scadenza breve e toglilo dalla GPO quando la distribuzione è finita;
- approva in console solo i PC che riconosci.

## Installazione manuale o da altri strumenti

```bat
msiexec /i openrmm-agent-1.0.0-x64.msi /qn ^
  SERVER=agent.cliente.it:443 ^
  ENROLLTOKEN=<token> ^
  ROOTCA=<base64 della root CA> ^
  JOBSIGNINGKEYS=ed25519:... ^
  MODULESIGNINGKEYS=ed25519:... ^
  RELEASESIGNINGKEYS=ed25519:... ^
  ALLOWADHOCSCRIPTS=1
```

I valori finiscono in `HKLM\SOFTWARE\open-rmm`. Al primo avvio l'agente:

- restringe i permessi di quella chiave a SYSTEM e Administrators;
- dopo la registrazione cancella il token.

## Cosa viene installato

| Elemento | Dove |
|---|---|
| Agente e watchdog | `C:\Program Files\open-rmm\versions\<versione>\` |
| Servizi | `openrmm-agent`, `openrmm-watchdog` (LocalSystem, avvio automatico ritardato, riavvio automatico in caso di errore) |
| Configurazione e stato | `C:\ProgramData\open-rmm\` (accesso solo a SYSTEM e Administrators) |
| Controllo periodico | Task schedulato `\open-rmm\Controllo servizi`, ogni 15 minuti |

Le impostazioni che l'MSI non può esprimere vengono applicate dai servizi stessi a ogni avvio:

- azioni di ripristino e avvio ritardato;
- task schedulato;
- permessi del registro e delle cartelle.

## Aggiornamenti e disinstallazione

- Dopo l'installazione l'agente **si aggiorna dalla console** ([AGGIORNAMENTI.md](AGGIORNAMENTI.md)), non con un nuovo MSI. Se ridistribuisci un MSI, usa una versione **non più vecchia** di quella che gli agenti hanno già: l'MSI riporta il servizio sulla propria versione.
- La disinstallazione (Programmi e funzionalità, `msiexec /x`, o rimozione dalla GPO) elimina servizi, task schedulato, tutte le versioni installate e lo stato dell'agente, compresa la sua chiave privata. In console l'agente va poi revocato.

## Verifiche fatte e limiti

- Le tabelle del pacchetto vengono controllate a ogni build: servizi, valori di registro, proprietà sicure, sequenza delle azioni.
- Il pacchetto è stato installato e disinstallato con l'msiexec di **Wine 10**. L'installazione con le proprietà è riuscita, entrambi i servizi sono partiti e l'agente si è registrato su un gateway reale, comparendo in attesa di approvazione. Il token è stato rimosso dal registro dopo la registrazione e la disinstallazione ha cancellato dati e chiave privata.
- **Non ancora provato su Windows reale:**
  - installazione via GPO;
  - permessi del registro e delle cartelle;
  - task schedulato;
  - ripartenza dopo l'arresto del servizio.
