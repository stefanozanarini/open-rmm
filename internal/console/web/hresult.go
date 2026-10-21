package web

// Windows Update error codes (HRESULT) seen most often, with what to do.
// Unknown codes are shown as they are; Microsoft documents them at
// learn.microsoft.com/windows/deployment/update/windows-update-error-reference.
var hresultTexts = map[string]string{
	"0x80240022": "tutti gli aggiornamenti dell'operazione non sono riusciti",
	"0x8024200D": "l'aggiornamento va scaricato di nuovo (download incompleto)",
	"0x80246007": "download non completato",
	"0x80240034": "download non riuscito",
	"0x8024402C": "server di Windows Update non raggiungibile (proxy o DNS)",
	"0x80244022": "server di Windows Update non disponibile (HTTP 503)",
	"0x80244018": "accesso negato dal proxy (HTTP 403)",
	"0x80072EE2": "timeout di rete verso Windows Update",
	"0x80072EFD": "connessione a Windows Update non riuscita",
	"0x80072F8F": "errore TLS verso Windows Update (data e ora del PC?)",
	"0x80070005": "accesso negato",
	"0x80070643": "errore irreversibile dell'installer (spesso .NET o Defender)",
	"0x800F0922": "installazione non riuscita (partizione di sistema piena o servicing interrotto)",
	"0x800F081F": "file di origine non trovati: riparare l'immagine con DISM",
	"0x800F0831": "manca un aggiornamento precedente richiesto",
	"0x80073712": "archivio dei componenti danneggiato: DISM /RestoreHealth",
	"0x80070570": "file danneggiato o illeggibile",
	"0x800705B4": "timeout dell'operazione",
	"0x8024001E": "operazione annullata (servizio arrestato o PC in spegnimento)",
	"0x80242016": "operazione dopo il riavvio non riuscita",
	"0x80240017": "aggiornamento non applicabile a questo sistema",
	"0x80070070": "spazio su disco insufficiente",
	"0x80070422": "servizio Windows Update disattivato",
	"0x8024000B": "operazione annullata",
	"0x80240016": "un'altra installazione è in corso",
	"0x80240FFF": "errore non specificato di Windows Update",
	"0x80070002": "file non trovato (cache di Windows Update da pulire)",
	"0x80070003": "percorso non trovato (cache di Windows Update da pulire)",
	"0x800F0988": "pulizia dei componenti necessaria: DISM /StartComponentCleanup",
}

// hresultText explains a failed installation: the code when known, the
// result otherwise.
func hresultText(code, result string) string {
	if t, ok := hresultTexts[code]; ok {
		return t
	}
	switch result {
	case "download_failed":
		return "download non riuscito"
	case "aborted":
		return "installazione interrotta"
	case "succeeded_with_errors":
		return "installato con errori"
	}
	return "installazione non riuscita"
}
