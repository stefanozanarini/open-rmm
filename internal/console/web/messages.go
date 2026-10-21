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
	// winget
	msg("Nessuna applicazione da aggiornare (winget)", "No applications to update (winget)"),
	msg("{} applicazioni da aggiornare: {}", "${1} applications to update: ${2}"),
	msg("winget non disponibile su questo endpoint: aggiornamenti delle applicazioni solo dal catalogo della console", "winget not available on this endpoint: application updates only from the console catalog"),
	// trendmicro
	msg("{} non installato", "${1} not installed"),
	msg("{}: installato, nessun servizio noto in esecuzione (verificare i nomi dei servizi)", "${1}: installed, no known service running (check the service names)"),
	msg("{} attivo", "${1} active"),
	// Vision One
	msg("Endpoint non presente nell'inventario di Vision One", "Endpoint not in the Vision One inventory"),
	msg("Endpoint non presente in Vision One (offline anche per open-rmm)", "Endpoint not in Vision One (offline for open-rmm too)"),
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
			groups[g] = trMessage(lang, groups[g])
		}
		return expand(m.en, groups)
	}
	// "<product>: servizio X assente, servizio Y Stopped" (trendmicro).
	if name, list, ok := strings.Cut(s, ": "); ok && strings.HasPrefix(list, "servizio ") {
		parts := strings.Split(list, ", ")
		for i, p := range parts {
			for _, m := range serviceProblems {
				if g := m.re.FindStringSubmatch(p); g != nil {
					parts[i] = expand(m.en, g)
					break
				}
			}
		}
		return name + ": " + strings.Join(parts, ", ")
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
