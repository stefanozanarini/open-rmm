# Installazione del server

La console gira in container su un host Linux con Docker e il plugin Compose. I file sono in [deploy/](../deploy).

| Container | Ruolo | Esposto |
|---|---|---|
| `gateway` | Endpoint degli agenti (mTLS) | Sì, porta `OPENRMM_PUBLIC_PORT` (default 443) |
| `db` | PostgreSQL 16 | No: rete interna senza accesso all'esterno |
| `admin` | Comandi di amministrazione, solo su richiesta | No |

Il gateway gira come utente non privilegiato (65532), con file system in sola lettura, nessuna capability Linux e limiti di memoria e processi.

## 1. Configurazione

```bash
cd deploy
cp .env.example .env
```

Imposta in `.env` due password diverse e sicure per l'URL (ad esempio `openssl rand -hex 24`): `POSTGRES_PASSWORD` per l'amministratore del database e `OPENRMM_DB_PASSWORD` per il ruolo applicativo `openrmm`. Al primo avvio lo script in `postgres-init/` crea il ruolo `openrmm` senza privilegi di superutente, perché un superutente scavalcherebbe l'isolamento tra tenant.

## 2. PKI

```bash
docker compose build
./setup-pki.sh agent.cliente.it
```

Lo script crea:

- `pki/ca/`: tutta la PKI. Distribuisci `root-ca.crt` agli agenti (MSI o GPO).
- `pki/gateway/`: i quattro file che servono al gateway, montati in sola lettura.

**Sposta `pki/ca/root-ca.key` fuori dal server** (ad esempio su una chiavetta cifrata in cassaforte) e cancellalo dall'host. Serve solo per emettere una nuova CA degli agenti.

Il nome DNS (`agent.cliente.it`) deve risolvere sull'host sia dalla LAN sia da internet. Il TLS viene terminato dal gateway: se davanti c'è un firewall o un reverse proxy, deve inoltrare la connessione TCP così com'è (passthrough), senza decifrarla.

## 3. Avvio

```bash
docker compose up -d
docker compose ps
```

Il gateway applica da solo le migrazioni del database all'avvio.

## 4. Tenant e token di enrollment

```bash
docker compose run --rm admin tenant create -name "Cliente"
docker compose run --rm admin token create -tenant <TENANT> -max-uses 250 -ttl 720h -description "GPO sede"
```

Per default **ogni nuovo agente resta in attesa** (`pending`) finché un operatore non lo approva: è connesso e visibile, ma non riceve comandi. Questo protegge dal caso in cui qualcuno legga il token dal registro (le chiavi di policy GPO sono leggibili da tutti gli utenti del dominio) e registri un agente falso.

Per un token di cui ti fidi completamente (ad esempio uno usato da un tecnico per un singolo PC) puoi attivare l'approvazione automatica:

```bash
docker compose run --rm admin token create -tenant <TENANT> -max-uses 1 -ttl 2h -auto-approve
```

## 5. Gestione degli agenti

```bash
docker compose run --rm admin agents list    -tenant <TENANT>
docker compose run --rm admin agents approve -tenant <TENANT> -agent <AGENT>
docker compose run --rm admin agents reject  -tenant <TENANT> -agent <AGENT>
docker compose run --rm admin audit verify   -tenant <TENANT>
```

`reject` e `revoke` sono equivalenti: l'agente viene disconnesso e non può più collegarsi.

## Certificati degli agenti

I certificati degli agenti durano 90 giorni. L'agente li rinnova da solo quando manca meno di un terzo della validità (circa 30 giorni), generando ogni volta una nuova chiave. Il certificato precedente resta valido finché l'agente non si collega con quello nuovo, così una risposta persa durante il rinnovo non lo lascia fuori.

Un PC rimasto spento per più di 90 giorni ha il certificato scaduto: se nella configurazione è ancora presente un token valido si registra di nuovo (come nuovo agente), altrimenti va reinstallato con un token nuovo.

## Backup

Il volume `db-data` contiene tutto lo stato della console. Esegui backup cifrati regolari, per esempio:

```bash
docker compose exec db pg_dump -U postgres -Fc openrmm > openrmm-$(date +%F).dump
```
