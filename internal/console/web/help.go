package web

import "html/template"

// Contextual help: a "?" next to page titles and some sections opens a
// short explanation (a <details> element: no script, closed by a click
// elsewhere in app.js). The texts are in the catalog like every string.

// helpTexts are keyed by page template name, or by "section:<name>".
var helpTexts = map[string]string{
	"agents":      "Elenco dei computer con l'agente. A sinistra filtri per sede, sistema operativo e OU di Active Directory; la casella di ricerca trova per nome, IP, utente o versione. Un clic su un computer apre il pannello in basso, il tasto destro il menu rapido. Con le caselle selezioni più computer per un'azione su tutti, approvata con una sola MFA.",
	"agent":       "Tutto su un computer: riepilogo, controlli, aggiornamenti, software, inventario, accessi e job. Le azioni (comandi, shell, file, installazioni) chiedono l'approvazione MFA: l'agente esegue solo comandi firmati.",
	"jobs":        "Ogni comando inviato agli agenti, con stato e risultato. \"Completato con errori\" vuol dire che il modulo ha funzionato ma alcuni elementi (aggiornamenti, applicazioni) non sono stati installati: apri il job per il dettaglio. Puoi filtrare per computer o cercare per modulo, azione e stato.",
	"job":         "Dettaglio di un comando: parametri firmati, avanzamento, risultato e log del modulo. Il riquadro in basso a destra mostra i tuoi job in corso su ogni pagina.",
	"patches":     "Riepilogo degli aggiornamenti di tutti i computer: Windows Update (o apt, dnf, zypper su Linux), applicazioni con winget e firmware. \"Aggiorna…\" su un'applicazione la aggiorna su tutti i computer che ne hanno bisogno con una sola approvazione.",
	"appupgrade":  "Aggiornamento di un'applicazione con winget su più computer: scegli la sede, controlla l'elenco e approva una sola volta. I computer spenti ricevono il comando quando si ricollegano.",
	"packages":    "Libreria del software: carichi un installer (MSI o EXE) o lo importi dal catalogo winget una volta sola, poi lo distribuisci su uno o più computer. I pacchetti senza firma Authenticode vanno consentiti esplicitamente.",
	"deploy":      "Distribuzione di un pacchetto: scegli i computer e approva con MFA. L'agente scarica il pacchetto dalla console e ne verifica l'impronta SHA-256 prima di installarlo.",
	"policies":    "Le policy dicono agli agenti cosa raccogliere o eseguire periodicamente: inventario, scansioni degli aggiornamenti, installazione dei tool del produttore, riavvii in finestra. Ogni policy è firmata; i moduli che eseguono script o aprono sessioni non possono stare in una policy.",
	"policy_form": "Per ogni modulo scegli le azioni da eseguire, ogni quanto e su quali computer (client, server, piattaforme). Al salvataggio la policy viene firmata e gli agenti la ricevono alla connessione successiva.",
	"reports":     "Cruscotto, ricerca dei computer per software, sistema, utente, modello o sede, sistemi operativi, accessi e vulnerabilità (CVE) calcolate dall'inventario. Da una CVE o da una ricerca per software puoi aprire l'azione di aggiornamento già preparata.",
	"alerts":      "Elenco degli avvisi di sicurezza: controlli non più superati, accessi RDP da reti non previste o da indirizzi nuovi, account bloccati, troppi accessi falliti. Riconosci un avviso quando l'hai gestito; si riapre se il problema si ripresenta.",
	"audit":       "Registro di audit: ogni azione degli operatori (approvazioni, comandi, sessioni shell e file con i file trasferiti, modifiche alle impostazioni) con autore e data. Non si può modificare dalla console.",
	"installers":  "Crea l'installer dell'agente, MSI per Windows o .run per Linux, già configurato con indirizzo della console, certificati e token di registrazione. I computer installati compaiono in attesa di approvazione.",
	"tokens":      "I token di registrazione permettono a un agente di presentarsi alla console, mai di essere approvato da solo. Dai loro una scadenza e revocali se un installer finisce in mani sbagliate.",
	"modules":     "I moduli firmati danno funzioni agli agenti (inventario, aggiornamenti, firmware, file…). Quelli inclusi nella console si pubblicano qui con una sola approvazione; una versione nuova va pubblicata prima di poterla usare.",
	"sites":       "Sedi e subnet: un computer va nella prima sede che contiene uno dei suoi indirizzi IP, dall'inventario o da cui si collega. Puoi anche assegnare una sede a mano dal pannello dell'agente.",
	"settings":    "Impostazioni del tenant: reti da cui l'RDP è consentito, limite per file della gestione dei file, logo aziendale.",
	"setup":       "Stato della configurazione della console: certificati, firma, collegamento a Entra ID, moduli e release da pubblicare.",
	"ad":          "Confronto tra i computer di Active Directory e gli agenti: trovi i PC che non hanno l'agente (forse non ricevono la GPO) e gli oggetti computer vecchi da pulire.",
	"federation":  "Collegamento con una console centrale: gli operatori centrali lavorano su questa console e ogni loro azione è registrata qui a loro nome.",
	"updates":     "Aggiornamenti dell'agente: release pubblicate e anelli. I computer dell'anello pilot ricevono subito la nuova versione, quelli broad dopo.",
	"bulk":        "Azioni su più computer insieme: comandi, script, installazioni, gestione dei file, sede e anello. Una sola autenticazione MFA approva l'azione su tutti; ogni computer riceve un proprio comando firmato.",
	"shell":       "Shell interattiva sul computer, a tempo. Ogni riga digitata è registrata nell'audit. Chiudi la sessione quando hai finito.",
	"files":       "Gestione dei file: \"Sfoglia\" sceglie il computer di cui vedi le cartelle; \"Applica a\" decide su quali computer caricare un file o da quali scaricarlo in uno zip. Le cartelle dell'agente non sono accessibili e ogni file trasferito è registrato.",

	"section:shell":    "Apre PowerShell (bash su Linux) sul computer per il tempo scelto, dopo l'approvazione MFA. Il computer deve consentirlo con la policy locale (GPO AllowInteractiveShell).",
	"section:files":    "Apre la gestione dei file sul computer per il tempo scelto, dopo l'approvazione MFA. Serve l'agente 1.1.0 o successivo e il modulo files pubblicato.",
	"section:blockers": "Impostazioni del computer che bloccano o limitano Windows Update: versione bloccata, server WSUS che non risponde, servizi disabilitati, pause, poco spazio. Vanno corrette sul computer o nella GPO che le imposta; per lo spazio, \"Libera spazio…\" svuota la cache di Windows Update ed esegue la Pulizia disco.",
	"section:firmware": "Versioni di BIOS, firmware dei dispositivi e driver installate ora, e aggiornamenti offerti dallo strumento del produttore (Dell Command Update, Lenovo System Update, HP Image Assistant). L'installazione sceglie i tipi e l'importanza; il BIOS solo se spuntato, con il PC collegato alla corrente. Il PC non viene riavviato.",
	"section:cve":      "Le vulnerabilità sono calcolate confrontando l'inventario con i dati di Microsoft, NVD e CISA (scaricati ogni 6 ore). In cima quelle sfruttate attivamente. Apri una CVE per i computer colpiti e l'azione di correzione.",
	"section:ring":     "pilot: riceve subito le nuove versioni dell'agente, per provarle su pochi computer. broad: le riceve dopo, quando la versione è promossa.",
	"section:ad":       "Albero dei domini e delle OU di Active Directory: un clic filtra i computer di quella OU. I numeri contano i computer con l'agente.",
}

// helpHTML renders the "?" of a key in lang, or nothing.
func helpHTML(lang, key string) template.HTML {
	text, ok := helpTexts[key]
	if !ok {
		return ""
	}
	label := template.HTMLEscapeString(tr(lang, "Aiuto"))
	body := template.HTMLEscapeString(tr(lang, text))
	return template.HTML(`<details class="help"><summary title="` + label + `" aria-label="` + label + `">?</summary>` +
		`<div class="help-pop" role="note">` + body + `</div></details>`) // #nosec G203 -- escaped above
}
