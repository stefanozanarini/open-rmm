# Aggiornamento dell'agente

L'agente si aggiorna da solo, versione per versione e per anelli, con ripristino automatico se la nuova versione non funziona.

## Come funziona

1. Sulla macchina offline si firma una **release**: agente e watchdog per una piattaforma, descritti da un manifest firmato con la **chiave di rilascio dell'agente**. È diversa dalle chiavi dei moduli e dei job.
2. La release viene pubblicata sulla console, che ne verifica la firma prima di accettarla.
3. Si imposta la **versione obiettivo** per un anello (`pilot` o `broad`) e una piattaforma.
4. Il gateway propone la release agli agenti di quell'anello che hanno una versione più vecchia. L'agente:
   - verifica la firma con le chiavi configurate sull'endpoint (`ReleaseSigningKeys`);
   - **rifiuta qualunque versione non più recente della propria**;
   - scarica gli eseguibili, ne controlla gli hash e li installa in `versions/<versione>/`, accanto alla versione attuale;
   - lascia al watchdog il compito di attivarla.
5. Il **watchdog** ricontrolla l'hash, ferma l'agente, punta il servizio alla nuova versione e lo riavvia. Su Windows cambia l'`ImagePath` del servizio, su Linux un drop-in systemd.
   - Se entro 10 minuti la nuova versione **non si ricollega alla console**, torna alla versione precedente.
   - Una versione ripristinata non viene più riproposta: serve una versione successiva.
6. La nuova versione dell'agente aggiorna poi il watchdog, con lo stesso meccanismo e rollback. I due non si aggiornano mai insieme, così ce n'è sempre uno in grado di sistemare l'altro.

Gli esiti (download, pronto, installato, rifiutato, ripristinato) arrivano in console, nella pagina dell'agente e in **Aggiornamenti**, e finiscono nel registro attività.

## Chiave di rilascio dell'agente

Si genera sulla macchina offline, come quella dei moduli:

```bash
openrmm-admin signing keygen -out agent-release.key
```

La chiave pubblica va configurata sugli agenti come `ReleaseSigningKeys` (REG_MULTI_SZ o `release_signing_keys` nel file di configurazione) e sulla console in `OPENRMM_RELEASE_KEYS`, per la verifica alla pubblicazione.

## Pubblicare una versione

La versione deve essere quella compilata negli eseguibili (`make build VERSION=1.2.0`). Il watchdog considera riuscito l'aggiornamento solo quando l'agente riporta esattamente quella versione.

```bash
# macchina offline
openrmm-admin release sign -version 1.2.0 -platform windows/amd64 \
  -agent bin/openrmm-agent.exe -watchdog bin/openrmm-watchdog.exe -key agent-release.key

# console
docker compose run --rm --user "$(id -u):$(id -g)" -v "$PWD:/in:ro" -e OPENRMM_RELEASE_KEYS admin \
  release publish -file /in/openrmm-1.2.0-windows-amd64.orel
```

## Rollout

```bash
# alcuni PC nell'anello pilota (gli altri restano in broad)
docker compose run --rm admin agents ring -tenant <TENANT> -agent <AGENT> -ring pilot

# prima il pilota...
docker compose run --rm admin release target -tenant <TENANT> -ring pilot -platform windows/amd64 -version 1.2.0
# ...dopo qualche giorno senza problemi, tutti
docker compose run --rm admin release target -tenant <TENANT> -ring broad -platform windows/amd64 -version 1.2.0

docker compose run --rm admin release list -tenant <TENANT>
```

Gli agenti connessi ricevono la proposta appena si imposta l'obiettivo, quelli spenti alla prossima connessione.

## Ripartenza automatica

| Livello | Windows | Linux |
|---|---|---|
| 1 | Azioni di ripristino del servizio: riavvio dopo 5 s, 30 s, poi ogni 2 minuti | `Restart=always` |
| 2 | Watchdog: riavvia l'agente se è fermo o se non aggiorna il file di salute da 5 minuti (al massimo 6 volte l'ora) | idem |
| 3 | Task schedulato ogni 15 minuti: `sc.exe start` su watchdog e agente | timer systemd `openrmm-healthcheck` |

Il terzo livello usa solo programmi di sistema con percorso fisso, quindi continua a funzionare qualunque versione sia installata.

## Limiti attuali

- Il meccanismo è provato con test automatici: switch, rollback, file manomessi, percorsi fuori dalla cartella delle versioni, limite ai riavvii, offerte firmate con chiavi non fidate, file alterati, anelli, downgrade. **Non è ancora stato provato su Windows reale né con systemd reale.**
- L'installazione iniziale (servizi, cartelle, task schedulato) sarà fatta dall'MSI. Per lo sviluppo esistono `openrmm-agent install` e `openrmm-watchdog install`.
