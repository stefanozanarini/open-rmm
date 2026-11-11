// Package filesession is the protocol of the interactive file sessions: an
// operator browses the folders of an agent, downloads and uploads files.
//
// A session is a signed job of a module with the file_session capability;
// its frames travel over the same stream as the interactive shell
// (ShellFrame.data), so the gateway, the relay and the broker carry them
// unchanged. Each frame's data is either
//
//	'J' + a JSON control message (Msg), or
//	'D' + a 4-byte big-endian transfer id + file bytes.
//
// The console asks, the agent answers: the agent never sends unasked, so the
// gateway (which drops frames when nobody listens) loses nothing. A
// download is paced by credits: the agent sends at most Window chunks the
// console has not acknowledged.
package filesession

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"
)

const (
	// ChunkSize is the size of the data frames.
	ChunkSize = 256 << 10
	// Window is how many chunks of a download may be unacknowledged.
	Window = 16
	// MaxEntries bounds a folder listing.
	MaxEntries = 5000
)

// Operations.
const (
	OpRoots  = "roots"   // console: the drives (Windows) or "/"; agent: Roots
	OpList   = "list"    // console: Path; agent: Path, Entries, Truncated
	OpGet    = "get"     // console: ID, Path
	OpFile   = "file"    // agent: ID, Size: a download starts
	OpEnd    = "end"     // agent: ID, SHA256: a download is complete
	OpAck    = "ack"     // console: ID, Credit
	OpPut    = "put"     // console: ID, Path, Size, Overwrite
	OpReady  = "ready"   // agent: ID: send the data
	OpPutEnd = "put-end" // console: ID, SHA256: all the data was sent
	OpMkdir  = "mkdir"   // console: ID, Path
	OpOK     = "ok"      // agent: ID: upload or mkdir done
	OpCancel = "cancel"  // console: ID
	OpError  = "error"   // agent: ID, Error
	OpClose  = "close"   // console: end of the session
)

// Msg is a control message. Paths are the agent's native, absolute paths.
type Msg struct {
	Op        string   `json:"op"`
	ID        uint32   `json:"id,omitempty"`
	Path      string   `json:"path,omitempty"`
	Size      int64    `json:"size,omitempty"`
	Overwrite bool     `json:"overwrite,omitempty"`
	SHA256    string   `json:"sha256,omitempty"`
	Credit    int      `json:"credit,omitempty"`
	Error     string   `json:"error,omitempty"`
	Entries   []Entry  `json:"entries,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`
	Roots     []string `json:"roots,omitempty"`
	// Sep is the agent's path separator (with roots and list).
	Sep string `json:"sep,omitempty"`
}

// Entry is an item of a folder.
type Entry struct {
	Name     string    `json:"name"`
	Dir      bool      `json:"dir,omitempty"`
	Size     int64     `json:"size,omitempty"`
	Modified time.Time `json:"modified"`
	Link     bool      `json:"link,omitempty"`
}

// EncodeMsg returns the frame data of a control message.
func EncodeMsg(m Msg) []byte {
	b, _ := json.Marshal(m)
	return append([]byte{'J'}, b...)
}

// EncodeData returns the frame data of a chunk of transfer id.
func EncodeData(id uint32, chunk []byte) []byte {
	b := make([]byte, 5+len(chunk))
	b[0] = 'D'
	binary.BigEndian.PutUint32(b[1:5], id)
	copy(b[5:], chunk)
	return b
}

// Decode splits frame data: a control message, or a chunk of transfer id.
func Decode(b []byte) (*Msg, uint32, []byte, error) {
	if len(b) == 0 {
		return nil, 0, nil, errors.New("empty frame")
	}
	switch b[0] {
	case 'J':
		var m Msg
		if err := json.Unmarshal(b[1:], &m); err != nil {
			return nil, 0, nil, err
		}
		return &m, 0, nil, nil
	case 'D':
		if len(b) < 5 {
			return nil, 0, nil, errors.New("short data frame")
		}
		return nil, binary.BigEndian.Uint32(b[1:5]), b[5:], nil
	}
	return nil, 0, nil, errors.New("unknown frame")
}
