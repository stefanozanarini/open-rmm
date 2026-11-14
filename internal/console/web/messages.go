package web

import (
	"regexp"
	"strings"
)

// Check and alert texts. Modules and the console's own checks write them
// in Italian, with values (counts, names, addresses) inside; they are
// stored as written and translated when shown, by matching the known
// sentences. Unknown text is shown as is.

type message struct {
	re *regexp.Regexp
	en string // replacement, $1... for the values
	// inner lists the groups that hold another message (e.g. the summary
	// inside a failed check alert), translated too.
	inner []int
}

// msg builds a message from an Italian pattern where {} stands for a value.
func msg(it, en string, inner ...int) message {
	parts := strings.Split(it, "{}")
	for i := range parts {
		parts[i] = regexp.QuoteMeta(parts[i])
	}
	return message{re: regexp.MustCompile("^" + strings.Join(parts, "(.*?)") + "$"), en: en, inner: inner}
}

var messages = []message{
	// Wrappers first: their inner text would match a sentence below.
	msg("Controllo {} non superato: {}", "Check ${1} failed: ${2}", 2),
	msg("Vision One: {}", "Vision One: ${1}", 1),
	// winupdate
	msg("{} aggiornamenti di sicurezza mancanti, {} usciti da più di {} giorni", "${1} missing security updates, ${2} released more than ${3} days ago"),
	msg("{} aggiornamenti di sicurezza mancanti, {} usciti da piÃ¹ di {} giorni", "${1} missing security updates, ${2} released more than ${3} days ago"),
	msg("{} aggiornamenti di sicurezza da installare", "${1} security updates to install"),
	msg("Nessun aggiornamento di sicurezza mancante ({} altri disponibili)", "No missing security updates (${1} others available)"),
	msg("Riavvio in sospeso da {} giorni", "Reboot pending for ${1} days"),
	msg("Nessun riavvio in sospeso", "No reboot pending"),
	msg("Aggiornamenti bloccati: {}", "Updates blocked: ${1}", 1),
	msg("Aggiornamenti limitati: {}", "Updates limited: ${1}", 1),
	msg("Nessuna impostazione blocca gli aggiornamenti", "No setting blocks updates"),
	// winupdate blockers
	msg("Versione di Windows bloccata a {} da policy (attuale: {}): le versioni successive non vengono offerte", "Windows version pinned to ${1} by policy (current: ${2}): later versions are not offered"),
	msg("Versione di Windows bloccata a {} da Intune/MDM (attuale: {}): le versioni successive non vengono offerte", "Windows version pinned to ${1} by Intune/MDM (current: ${2}): later versions are not offered"),
	msg("Versione di Windows bloccata in UpdatePolicy\\PolicyState ({}) senza una policy che la imposti: probabilmente un residuo da rimuovere", "Windows version pinned in UpdatePolicy\\PolicyState (${1}) with no policy setting it: probably a leftover to remove"),
	msg("Accesso a Windows Update disattivato da policy (DisableWindowsUpdateAccess)", "Access to Windows Update turned off by policy (DisableWindowsUpdateAccess)"),
	msg("Server WSUS {} non raggiungibile", "WSUS server ${1} unreachable"),
	msg("Indirizzo del server WSUS non valido: {}", "Invalid WSUS server address: ${1}"),
	msg("Server WSUS {} raggiungibile ma il servizio non risponde ({})", "WSUS server ${1} reachable but the service does not answer (${2})"),
	msg("Server WSUS attivato (UseWUServer) ma nessun indirizzo configurato (WUServer)", "WSUS server turned on (UseWUServer) but no address configured (WUServer)"),
	msg("Server WSUS {} configurato: nessuna ricerca di aggiornamenti riuscita da {} giorni", "WSUS server ${1} configured: no successful update search for ${2} days"),
	msg("Server WSUS {} configurato: nessun aggiornamento installato da {} giorni (il server non approva più aggiornamenti?)", "WSUS server ${1} configured: no update installed for ${2} days (does the server still approve updates?)"),
	msg("Windows Update disattivato da policy (NoWindowsUpdate)", "Windows Update turned off by policy (NoWindowsUpdate)"),
	msg("Accesso a Windows Update disattivato da Gestione comunicazioni Internet (DisableWindowsUpdateAccess)", "Access to Windows Update turned off by Internet Communication Management (DisableWindowsUpdateAccess)"),
	msg("Il file hosts reindirizza i server di Windows Update: {}", "The hosts file redirects the Windows Update servers: ${1}"),
	msg("Connessione a Windows Update su internet disattivata (DoNotConnectToWindowsUpdateInternetLocations) senza un server WSUS", "Connection to Windows Update on the internet turned off (DoNotConnectToWindowsUpdateInternetLocations) without a WSUS server"),
	msg("Aggiornamenti automatici disattivati da policy (NoAutoUpdate): li installa open-rmm", "Automatic updates turned off by policy (NoAutoUpdate): Tempra RMM installs them"),
	msg("Aggiornamenti di qualità differiti di {} giorni da policy", "Quality updates deferred by ${1} days by policy"),
	msg("Aggiornamenti di funzionalità differiti di {} giorni da policy", "Feature updates deferred by ${1} days by policy"),
	msg("Aggiornamenti in pausa fino al {}", "Updates paused until ${1}"),
	msg("Driver esclusi dagli aggiornamenti di qualità da policy (ExcludeWUDriversInQualityUpdate)", "Drivers excluded from quality updates by policy (ExcludeWUDriversInQualityUpdate)"),
	msg("Servizio {} disabilitato", "Service ${1} disabled"),
	msg("Spazio libero insufficiente su {} ({} GB)", "Not enough free space on ${1} (${2} GB)"),
	msg("Poco spazio libero su {} ({} GB)", "Low free space on ${1} (${2} GB)"),
	// protection-status
	msg("Nessun antivirus attivo registrato in Sicurezza di Windows", "No active antivirus registered in Windows Security"),
	msg("Antivirus non aggiornato: {}", "Antivirus out of date: ${1}"),
	msg("Antivirus attivo: {}", "Antivirus active: ${1}"),
	msg("Microsoft Defender: protezione in tempo reale disattivata", "Microsoft Defender: real-time protection off"),
	msg("Microsoft Defender: firme vecchie di {} giorni", "Microsoft Defender: signatures ${1} days old"),
	msg("Microsoft Defender attivo e aggiornato", "Microsoft Defender active and up to date"),
	msg("Windows Firewall disattivato per: {}", "Windows Firewall off for: ${1}"),
	msg("Windows Firewall attivo su tutti i profili", "Windows Firewall on for all profiles"),
	// firmware
	msg("Dell Command Update non installato: distribuiscilo dalla pagina Software (Dell.CommandUpdate)", "Dell Command Update not installed: deploy it from the Software page (Dell.CommandUpdate)"),
	msg("Lenovo System Update non installato: distribuiscilo dalla pagina Software (Lenovo.SystemUpdate)", "Lenovo System Update not installed: deploy it from the Software page (Lenovo.SystemUpdate)"),
	msg("HP Image Assistant non installato: distribuiscilo dalla pagina Software", "HP Image Assistant not installed: deploy it from the Software page"),
	msg("Modello HP non supportato da HP Image Assistant", "HP model not supported by HP Image Assistant"),
	msg("Produttore {} non supportato per gli aggiornamenti firmware", "Manufacturer ${1} not supported for firmware updates"),
	msg("BIOS, firmware e driver aggiornati", "BIOS, firmware and drivers up to date"),
	msg("{} aggiornamenti firmware/driver, BIOS da aggiornare, {} critici", "${1} firmware/driver updates, BIOS to update, ${2} critical"),
	msg("{} aggiornamenti firmware/driver, BIOS da aggiornare", "${1} firmware/driver updates, BIOS to update"),
	msg("{} aggiornamenti firmware/driver, {} critici", "${1} firmware/driver updates, ${2} critical"),
	msg("{} aggiornamenti firmware/driver", "${1} firmware/driver updates"),
	// inventory (domain controllers)
	msg("Membri non predefiniti nei gruppi privilegiati del dominio: {}", "Non-standard members in the domain privileged groups: ${1}"),
	msg("Gruppi privilegiati del dominio con i soli membri predefiniti", "Domain privileged groups with only their default members"),
	// inventory (battery wear)
	msg("Batteria usurata, salute {}", "Battery worn, health ${1}"),
	msg("Batteria in usura, salute {}", "Battery wearing, health ${1}"),
	msg("Batteria in buona salute, {}", "Battery in good health, ${1}"),
	// winget
	msg("Nessuna applicazione da aggiornare (winget)", "No applications to update (winget)"),
	msg("{} applicazioni da aggiornare: {}", "${1} applications to update: ${2}"),
	msg("winget non disponibile su questo endpoint: aggiornamenti delle applicazioni solo dal catalogo della console", "winget not available on this endpoint: application updates only from the console catalog"),
	// trendmicro
	msg("{} non installato", "${1} not installed"),
	msg("{} non installato (non richiesto)", "${1} not installed (not required)"),
	msg("{}: installato, nessun servizio noto in esecuzione (verificare i nomi dei servizi)", "${1}: installed, no known service running (check the service names)"),
	msg("{} attivo", "${1} active"),
	// Vision One
	msg("Endpoint non presente nell'inventario di Vision One", "Endpoint not in the Vision One inventory"),
	msg("Endpoint non presente in Vision One (offline anche per Tempra RMM)", "Endpoint not in Vision One (offline for Tempra RMM too)"),
	msg("Endpoint non presente in Vision One (offline anche per open-rmm)", "Endpoint not in Vision One (offline for Tempra RMM too)"), // before the rename
	msg("Agente di protezione non connesso a Vision One dal {}, ma il PC è online, componenti non aggiornati", "Protection agent not connected to Vision One since ${1}, but the PC is online, components out of date"),
	msg("Agente di protezione non connesso a Vision One dal {}, ma il PC è online", "Protection agent not connected to Vision One since ${1}, but the PC is online"),
	msg("Protezione endpoint {}, versione {}, componenti non aggiornati", "Endpoint protection ${1}, version ${2}, components out of date"),
	msg("Protezione endpoint {}, versione {}", "Endpoint protection ${1}, version ${2}"),
	msg("Vision One Workbench {}: {} (gravità {}, punteggio {})", "Vision One Workbench ${1}: ${2} (severity ${3}, score ${4})"),
	// Alerts raised by the console.
	msg("Troppi eventi di accesso in una sola raccolta: alcuni non sono stati letti", "Too many logon events in one collection: some were not read"),
	msg("Accesso RDP di {} da {}, fuori dalle reti consentite", "RDP logon of ${1} from ${2}, outside the allowed networks"),
	msg("Accesso RDP di {} da un indirizzo mai visto prima: {}", "RDP logon of ${1} from a never seen address: ${2}"),
	msg("Account {} bloccato per troppi tentativi", "Account ${1} locked out after too many attempts"),
	msg("{} accessi falliti su {} utenti diversi da {} (possibile password spraying)", "${1} failed logons on ${2} different users from ${3} (possible password spraying)"),
	msg("{} accessi falliti da {}", "${1} failed logons from ${2}"),
}

// trendmicro: the problems listed after the product name.
var serviceProblems = []message{
	msg("servizio {} assente", "service ${1} missing"),
	msg("servizio {} disabilitato", "service ${1} disabled"),
	msg("servizio {} {}", "service ${1} ${2}"),
	msg("non attivo secondo il Centro sicurezza di Windows", "not active according to the Windows Security Center"),
}

// trMessage translates a check or alert text into lang.
func trMessage(lang, s string) string {
	if lang != langEN || s == "" {
		return s
	}
	for _, m := range messages {
		idx := m.re.FindStringSubmatchIndex(s)
		if idx == nil {
			continue
		}
		groups := make([]string, len(idx)/2)
		for i := range groups {
			if idx[2*i] >= 0 {
				groups[i] = s[idx[2*i]:idx[2*i+1]]
			}
		}
		for _, g := range m.inner {
			// Inner text may be several sentences joined by "; ".
			parts := strings.Split(groups[g], "; ")
			for i := range parts {
				parts[i] = trMessage(lang, parts[i])
			}
			groups[g] = strings.Join(parts, "; ")
		}
		return expand(m.en, groups)
	}
	// "<product>: servizio X assente, servizio Y Stopped" or "<product>: non
	// attivo secondo il Centro sicurezza di Windows" (trendmicro problems).
	if name, list, ok := strings.Cut(s, ": "); ok {
		parts := strings.Split(list, ", ")
		matched := false
		for i, p := range parts {
			for _, m := range serviceProblems {
				if g := m.re.FindStringSubmatch(p); g != nil {
					parts[i] = expand(m.en, g)
					matched = true
					break
				}
			}
		}
		if matched {
			return name + ": " + strings.Join(parts, ", ")
		}
	}
	return s
}

// expand replaces ${n} in tmpl with groups[n].
func expand(tmpl string, groups []string) string {
	var b strings.Builder
	for {
		i := strings.Index(tmpl, "${")
		if i < 0 {
			b.WriteString(tmpl)
			return b.String()
		}
		j := strings.IndexByte(tmpl[i:], '}')
		if j < 0 {
			b.WriteString(tmpl)
			return b.String()
		}
		b.WriteString(tmpl[:i])
		n := 0
		for _, c := range tmpl[i+2 : i+j] {
			n = n*10 + int(c-'0')
		}
		if n < len(groups) {
			b.WriteString(groups[n])
		}
		tmpl = tmpl[i+j+1:]
	}
}
