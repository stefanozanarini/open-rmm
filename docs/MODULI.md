# Moduli

Tutte le funzionalità di open-rmm sono moduli: l'agente sa solo scaricarli, verificarli ed eseguirli. Una funzionalità nuova si aggiunge pubblicando un modulo, **senza aggiornare l'agente**.

## Catena di fiducia

```
chiave di rilascio moduli (offline)
  └── firma il manifest
        ├── SHA-256 dell'archivio
        └── SHA-256 e dimensione di ogni file
chiave di firma dei job
  └── firma il job
        └── SHA-256 del manifest firmato  →  versione esatta del modulo
```

Prima di ogni esecuzione l'agente verifica:

1. la firma del job, che sia destinato a lui, la scadenza e che non l'abbia già ricevuto;
2. la firma del manifest, con una chiave di rilascio moduli configurata sull'endpoint;
3. che l'hash del manifest sia quello indicato nel job;
4. archivio e file estratti: hash e dimensioni, senza file in più, senza percorsi pericolosi;
5. di nuovo gli hash dei file in cache, subito prima dell'avvio;
6. la policy locale: per esempio un modulo con capability `adhoc_script` viene rifiutato se `AllowAdHocScripts` è 0.

La console non può firmare moduli: al massimo distribuisce moduli già firmati.

## Struttura di un modulo

```
modules/sysinfo/
  manifest.json
  Main.ps1        entrypoint Windows (PowerShell)
  main.sh         entrypoint Linux (sh)
```

Al momento della firma viene aggiunto automaticamente l'SDK in `_sdk/` (`OpenRmm.psm1` per PowerShell, `openrmm.sh` per sh).

### manifest.json

```json
{
  "id": "sysinfo",
  "version": "1.0.0",
  "description": "Basic host information",
  "protocol_version": 1,
  "entrypoints": {
    "windows/amd64": { "type": "powershell", "path": "Main.ps1" },
    "linux/amd64":   { "type": "sh",         "path": "main.sh" }
  },
  "actions": {
    "info": { "description": "Hostname, OS, uptime", "timeout_seconds": 120 }
  },
  "capabilities": []
}
```

| Campo | Note |
|---|---|
| `id` | minuscole, cifre e trattini, 2-41 caratteri |
| `version` | `x.y.z`. Una versione pubblicata non si può modificare: si pubblica una versione nuova |
| `entrypoints` | per piattaforma `GOOS/GOARCH`. Tipi: `powershell` (Windows PowerShell 5.1, o `pwsh` su Linux), `binary` (eseguibile), `sh` (Linux) |
| `actions` | `timeout_seconds` (default 600, massimo 14400). `context: "user"` è riservato all'esecuzione nella sessione utente, non ancora disponibile |
| `capabilities` | `adhoc_script` per i moduli che eseguono codice ricevuto nel job |

## Protocollo (versione 1)

L'agente avvia l'entrypoint in una cartella di lavoro temporanea, con un ambiente minimo: le variabili d'ambiente del servizio non vengono passate, salvo quelle di sistema indispensabili. Su stdin scrive **una riga JSON**:

```json
{"protocol_version":1,"job_id":"…","action":"info","params":{…},"tenant_id":"…","agent_id":"…","work_dir":"…"}
```

Il modulo scrive su stdout righe JSON:

| Evento | Esempio |
|---|---|
| avanzamento | `{"type":"progress","percent":40,"message":"lettura dischi"}` |
| log | `{"type":"log","level":"warn","message":"…"}` |
| risultato (finale) | `{"type":"result","data":{…}}` |
| errore (finale) | `{"type":"error","message":"…"}` |

Ci deve essere esattamente un evento finale. Le righe che non sono eventi vengono registrate come log, quindi output imprevisto (frequente in PowerShell) non rompe il protocollo. I limiti sono: riga 1 MB, output totale 16 MB, risultato 3 MB, stderr conservato 64 KB. Se il modulo li supera, viola il protocollo o va oltre il timeout, l'agente termina lui e tutti i suoi processi figli (process group su Linux, Job Object su Windows).

## Scrivere un modulo PowerShell

```powershell
Import-Module (Join-Path $PSScriptRoot '_sdk/OpenRmm.psm1')

Invoke-RmmModule @{
    info = {
        param($Params, $Request)
        Send-RmmProgress 50 'lettura sistema operativo'
        $os = Get-CimInstance Win32_OperatingSystem
        @{ os = $os.Caption; build = $os.BuildNumber }   # il valore restituito è il risultato
    }
}
```

Funzioni dell'SDK: `Invoke-RmmModule`, `Send-RmmProgress`, `Send-RmmLog`, `Send-RmmResult`, `Send-RmmError`, `Read-RmmRequest`. Un'eccezione nel blocco diventa un evento di errore con la posizione nel codice.

## Firmare e pubblicare

La firma va fatta sulla macchina offline che custodisce la chiave di rilascio moduli:

```bash
# una tantum: chiave di rilascio moduli (custodire offline)
openrmm-admin signing keygen -out module-release.key

openrmm-admin module sign -dir modules/sysinfo -key module-release.key
# → sysinfo-1.0.0.ormm
```

Poi, sul server della console:

```bash
export OPENRMM_MODULE_KEYS='ed25519:…'      # chiavi pubbliche di rilascio accettate
docker compose run --rm --user "$(id -u):$(id -g)" -v "$PWD:/in:ro" -e OPENRMM_MODULE_KEYS admin module publish -file /in/sysinfo-1.0.0.ormm
docker compose run --rm admin module list
```

`--user` serve perché il container legga i file locali, che hanno permessi riservati al tuo utente. La console verifica firma ed estrazione prima di pubblicare, così un pacchetto difettoso non arriva mai agli endpoint.

## Eseguire un job

```bash
docker compose run --rm --user "$(id -u):$(id -g)" -v "$PWD:/in:ro" admin job run \
  -tenant <TENANT> -agent <AGENT> -module sysinfo -version 1.0.0 -action info \
  -key /in/job-signing.key -wait
```

Per il modulo `script`:

```bash
docker compose run --rm --user "$(id -u):$(id -g)" -v "$PWD:/in:ro" admin job run -tenant <TENANT> -agent <AGENT> \
  -module script -version 1.0.0 -action run -script-file /in/diagnostica.ps1 -key /in/job-signing.key -wait
```

Il testo completo dello script finisce nell'audit log.

> **Provvisorio.** Oggi `job run` firma con una chiave passata da riga di comando e senza MFA. Nel prossimo passo la firma passa al servizio separato `openrmm-signer`, che firma solo dopo aver verificato permessi e MFA dell'operatore per quel job specifico.

## Moduli inclusi

| Modulo | Piattaforme | Azioni |
|---|---|---|
| `sysinfo` 1.0.0 | Windows, Linux | `info`: hostname, sistema operativo, uptime |
| `script` 1.0.0 | Windows | `run`: esegue `params.script` (PowerShell) e restituisce output, errori e durata. Capability `adhoc_script` |
