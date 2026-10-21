package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"sort"
	"strings"
)

// Job results shown as text: a sentence for the outcome of the common
// actions, then the fields as a list of labelled values, lists of records
// as tables. The JSON stays available, folded, for troubleshooting.

const (
	maxResultRows  = 50 // rows of a table
	maxResultDepth = 4
)

// resultKeys are the field names of module results, as labels.
var resultKeys = map[string]string{
	"exit_code": "codice di uscita", "reboot_required": "riavvio richiesto", "signer": "firmato da", "signature": "firma",
	"product_code": "codice prodotto", "product_name": "prodotto", "product_version": "versione",
	"method": "metodo", "name": "nome", "version": "versione", "title": "titolo", "kbs": "KB", "result": "esito",
	"date": "data", "reason": "motivo", "reasons": "motivi", "pending": "riavvio in sospeso", "delay_seconds": "attesa (secondi)",
	"users_logged_on": "utenti collegati", "installed": "installati", "action": "azione", "id": "id", "available": "disponibile",
	"source": "origine", "updates": "aggiornamenti", "upgrades": "aggiornamenti", "scanned_at": "verificato il", "status": "stato",
	"summary": "dettaglio", "checks": "controlli", "managed_by": "gestione", "wsus_server": "server WSUS", "since": "dal",
	"required": "richiesto", "classification": "classificazione", "severity": "gravità", "size_bytes": "dimensione (byte)",
	"collected_at": "raccolto il", "message": "messaggio", "error": "errore", "count": "numero", "path": "percorso",
	"scheduled": "programmato", "skipped": "saltato", "already_scheduled": "già programmato", "succeeded_with_errors": "completato con errori",
	"download_failed": "download non riuscito", "aborted": "interrotto", "not_started": "non avviato", "in_progress": "in corso",
	"quiet_uninstall_string": "comando di disinstallazione silenziosa", "uninstall_string_with_args": "comando di disinstallazione con argomenti",
	"removed": "rimosso", "upgraded": "aggiornate", "package": "pacchetto", "silent_args": "argomenti silenziosi", "uninstall_args": "argomenti di disinstallazione",
	"classifications": "classificazioni", "include_kbs": "KB da includere", "exclude_kbs": "KB da escludere", "allow_managed": "anche se gestito da WSUS o Intune", "pending_reboot": "riavvio in sospeso", "searcher": "ricerca",
}

func resultLabel(lang, k string) string {
	if l, ok := resultKeys[k]; ok {
		return tr(lang, l)
	}
	if l, ok := labels[k]; ok {
		return tr(lang, l)
	}
	return strings.ReplaceAll(k, "_", " ")
}

// exitCodes explains the installer exit codes that are not failures.
func exitCodeText(lang string, code string) string {
	switch code {
	case "0":
		return tr(lang, "riuscito")
	case "3010":
		return tr(lang, "riuscito, riavvio richiesto")
	case "1641":
		return tr(lang, "riuscito, riavvio avviato dall'installer")
	}
	return ""
}

// jobOutcome is a sentence for the result of the common actions.
func jobOutcome(lang, module, action string, res map[string]any) string {
	str := func(k string) string {
		if v, ok := res[k]; ok && v != nil {
			return strings.TrimSpace(fmt.Sprint(v))
		}
		return ""
	}
	reboot := res["reboot_required"] == true
	switch module + "/" + action {
	case "software/install":
		s := trf(lang, "Installato: %s", strings.TrimSpace(str("product_name")+" "+str("product_version")))
		if str("product_name") == "" {
			s = tr(lang, "Installazione completata.")
		}
		if reboot {
			s += " · " + tr(lang, "riavvio richiesto per completarla")
		}
		return s
	case "software/uninstall":
		s := tr(lang, "Disinstallazione completata.")
		if n := str("name"); n != "" {
			s = trf(lang, "Disinstallato: %s", strings.TrimSpace(n+" "+str("version")))
		}
		if reboot {
			s += " · " + tr(lang, "riavvio richiesto per completarla")
		} else if res["removed"] == false {
			s += " · " + tr(lang, "l'applicazione risulta ancora installata")
		}
		return s
	case "reboot/reboot":
		switch str("action") {
		case "scheduled":
			return trf(lang, "Riavvio programmato tra %s secondi.", str("delay_seconds"))
		case "already_scheduled":
			return tr(lang, "Un riavvio era già programmato.")
		case "skipped":
			return trf(lang, "Riavvio non eseguito: %s", resultLabel(lang, str("reason")))
		}
	case "winget/upgrade":
		list, _ := res["upgraded"].([]any)
		ok := 0
		for _, u := range list {
			if m, _ := u.(map[string]any); m != nil && m["ok"] == true {
				ok++
			}
		}
		return trf(lang, "%d applicazioni aggiornate su %d.", ok, len(list))
	case "winupdate/install":
		list, _ := res["installed"].([]any)
		ok := 0
		for _, u := range list {
			if m, _ := u.(map[string]any); m != nil && (m["result"] == "succeeded" || m["result"] == "succeeded_with_errors") {
				ok++
			}
		}
		if len(list) == 0 {
			return tr(lang, "Nessun aggiornamento da installare.")
		}
		s := trf(lang, "%d aggiornamenti installati su %d.", ok, len(list))
		if p, _ := res["pending_reboot"].(map[string]any); p != nil && p["required"] == true {
			s += " · " + tr(lang, "riavvio richiesto per completarla")
		}
		return s
	}
	if strings.HasSuffix(action, "scan") || strings.HasSuffix(action, "collect") || strings.HasSuffix(action, "status") {
		return tr(lang, "Dati raccolti: li trovi nella pagina dell'agente.")
	}
	return ""
}

// renderResult turns a job result into HTML; every value is escaped.
func renderResult(lang string, raw []byte, skip ...string) template.HTML {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return ""
	}
	if m, ok := v.(map[string]any); ok {
		for _, k := range skip {
			delete(m, k)
		}
	}
	var b strings.Builder
	writeValue(&b, lang, "", v, 0)
	return template.HTML(b.String()) // #nosec G203 -- built from escaped values
}

func esc(s string) string { return html.EscapeString(s) }

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// scalar formats a value that is not an object or a list.
func scalar(lang, key string, v any) string {
	switch x := v.(type) {
	case nil:
		return "-"
	case bool:
		if x {
			return esc(tr(lang, "sì"))
		}
		return esc(tr(lang, "no"))
	case json.Number:
		s := x.String()
		if key == "exit_code" {
			if t := exitCodeText(lang, s); t != "" {
				return esc(s) + ` <span class="muted">(` + esc(t) + `)</span>`
			}
		}
		return esc(s)
	case string:
		if x == "" {
			return "-"
		}
		switch key {
		case "result", "status", "action", "state", "method", "reason", "reasons", "managed_by", "classification", "severity", "classifications":
			if _, ok := resultKeys[x]; ok {
				return esc(resultLabel(lang, x))
			}
			if l, ok := labels[x]; ok {
				return esc(tr(lang, l))
			}
		case "summary":
			return esc(trMessage(lang, x))
		}
		return esc(x)
	}
	return esc(fmt.Sprint(v))
}

func isScalar(v any) bool {
	switch v.(type) {
	case map[string]any, []any:
		return false
	}
	return true
}

func writeValue(b *strings.Builder, lang, key string, v any, depth int) {
	switch x := v.(type) {
	case map[string]any:
		if len(x) == 0 {
			b.WriteString("-")
			return
		}
		if depth >= maxResultDepth {
			b.WriteString(`<span class="muted">…</span>`)
			return
		}
		b.WriteString(`<dl class="facts result">`)
		for _, k := range sortedKeys(x) {
			b.WriteString("<dt>" + esc(resultLabel(lang, k)) + "</dt><dd>")
			writeValue(b, lang, k, x[k], depth+1)
			b.WriteString("</dd>")
		}
		b.WriteString("</dl>")
	case []any:
		if len(x) == 0 {
			b.WriteString(`<span class="muted">` + esc(tr(lang, "nessuno")) + `</span>`)
			return
		}
		allScalar := true
		for _, e := range x {
			allScalar = allScalar && isScalar(e)
		}
		if allScalar {
			parts := make([]string, len(x))
			for i, e := range x {
				parts[i] = scalar(lang, key, e)
			}
			b.WriteString(strings.Join(parts, ", "))
			return
		}
		writeTable(b, lang, x, depth)
	default:
		b.WriteString(scalar(lang, key, v))
	}
}

// writeTable shows a list of records, one column per field.
func writeTable(b *strings.Builder, lang string, rows []any, depth int) {
	seen := map[string]bool{}
	var cols []string
	for _, r := range rows {
		if m, ok := r.(map[string]any); ok {
			for _, k := range sortedKeys(m) {
				if !seen[k] {
					seen[k] = true
					cols = append(cols, k)
				}
			}
		}
	}
	b.WriteString("<table><thead><tr>")
	for _, c := range cols {
		b.WriteString("<th>" + esc(resultLabel(lang, c)) + "</th>")
	}
	b.WriteString("</tr></thead><tbody>")
	for i, r := range rows {
		if i == maxResultRows {
			break
		}
		b.WriteString("<tr>")
		m, ok := r.(map[string]any)
		if !ok {
			b.WriteString(`<td colspan="` + fmt.Sprint(max(1, len(cols))) + `">`)
			writeValue(b, lang, "", r, depth+1)
			b.WriteString("</td></tr>")
			continue
		}
		for _, c := range cols {
			b.WriteString("<td>")
			if c == "status" {
				if s, ok := m[c].(string); ok {
					b.WriteString(`<span class="badge chk-` + esc(s) + `">` + scalar(lang, c, s) + `</span></td>`)
					continue
				}
			}
			if val, ok := m[c]; ok {
				writeValue(b, lang, c, val, depth+1)
			}
			b.WriteString("</td>")
		}
		b.WriteString("</tr>")
	}
	b.WriteString("</tbody></table>")
	if len(rows) > maxResultRows {
		b.WriteString(`<p class="muted small">` + esc(trf(lang, "Mostrate %d righe su %d.", maxResultRows, len(rows))) + `</p>`)
	}
}
