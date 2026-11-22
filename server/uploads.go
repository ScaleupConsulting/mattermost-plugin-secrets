package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
	"github.com/mattermost/mattermost/server/public/pluginapi"
	"github.com/pkg/errors"
)

const (
	keyPrefixUpload     = "up_"
	keyPrefixChunk      = "fc_"
	keyPrefixUploadRate = "ur_"

	// fileChunkBytes is the plaintext size of every chunk but the last; the server chooses it.
	fileChunkBytes = 4 << 20
	// chunkTagBytes is the AES-GCM tag each stored chunk carries on top of its plaintext.
	chunkTagBytes = 16
	// fileSlackBytes lets a relay that wraps the file (e.g. in PGP) exceed the limit slightly.
	fileSlackBytes = 64 << 10
	// maxChunkIndex keeps chunk keys to four digits.
	maxChunkIndex = 9999

	maxOpenUploadsPerUser = 2
	maxUploadsPerHour     = 10

	uploadStateOpen     = "open"
	uploadStateAttached = "attached"
)

// errUploadRateLimited is returned when a user starts too many uploads in an hour.
var errUploadRateLimited = errors.New("upload rate limited")

// statusError is an error whose message is safe to show the caller, with the HTTP status to use.
type statusError struct {
	status int
	msg    string
}

// Error returns the user-facing message.
func (e *statusError) Error() string { return e.msg }

// newStatusError builds a statusError.
func newStatusError(status int, msg string) error {
	return &statusError{status: status, msg: msg}
}

// writeStatusError sends a statusError as is and anything else as a generic 500.
func (p *Plugin) writeStatusError(w http.ResponseWriter, err error, fallback string) {
	var se *statusError
	if errors.As(err, &se) {
		writeError(w, se.status, se.msg)
		return
	}
	p.API.LogError(fallback, "err", err.Error())
	writeError(w, http.StatusInternalServerError, fallback)
}

// uploadSession tracks one sender's encrypted file while it is uploaded and until its secret burns.
type uploadSession struct {
	ID        string `json:"upload_id"`
	UserID    string `json:"user_id"`
	ChannelID string `json:"channel_id"`
	MaxBytes  int64  `json:"max_bytes"`
	ChunkSize int64  `json:"chunk_size"`
	MaxChunks int    `json:"max_chunks"`
	// ChunkBytes is the stored ciphertext length of each chunk index; 0 means not received.
	ChunkBytes    []int64 `json:"chunk_bytes"`
	BytesReceived int64   `json:"bytes_received"`
	State         string  `json:"state"`
	PostID        string  `json:"post_id,omitempty"`
	Chunks        int     `json:"chunks,omitempty"`
	Bytes         int64   `json:"bytes,omitempty"`
	CreatedAt     int64   `json:"created_at"`
	ExpiresAt     int64   `json:"expires_at"`
}

// reservedBytes is what a session counts against storage limits: the cap while open, the file once attached.
func (s *uploadSession) reservedBytes() int64 {
	if s.State == uploadStateAttached {
		return s.Bytes
	}
	return s.MaxBytes
}

// fileRef is the file part of a create-secret request.
type fileRef struct {
	UploadID string `json:"upload_id"`
	Chunks   int    `json:"chunks"`
	Bytes    int64  `json:"bytes"`
}

// chunkKey names the raw KV row holding one encrypted chunk.
func chunkKey(uploadID string, n int) string {
	return fmt.Sprintf("%s%s_%04d", keyPrefixChunk, uploadID, n)
}

// lockUpload serialises changes to one upload on this node and returns the unlock function.
func (p *Plugin) lockUpload(uploadID string) func() {
	m, _ := p.uploadLocks.LoadOrStore(uploadID, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// getUpload reads an upload session.
func (p *Plugin) getUpload(uploadID string) (*uploadSession, bool, error) {
	var s uploadSession
	found, err := p.getJSON(keyPrefixUpload+uploadID, &s)
	if err != nil || !found {
		return nil, found, err
	}
	return &s, true, nil
}

// updateUpload applies change to an upload session with compare-and-set, so other nodes' writes are not lost.
func (p *Plugin) updateUpload(uploadID string, change func(*uploadSession) error) error {
	return p.client.KV.SetAtomicWithRetries(keyPrefixUpload+uploadID, func(old []byte) (any, error) {
		if len(old) == 0 {
			return nil, errors.New("upload session is gone")
		}
		var s uploadSession
		if err := json.Unmarshal(old, &s); err != nil {
			return nil, err
		}
		if err := change(&s); err != nil {
			return nil, err
		}
		return json.Marshal(s)
	})
}

// deleteUpload removes an upload's chunks and session. maxChunks is used when the session is already gone.
func (p *Plugin) deleteUpload(uploadID string, maxChunks int) error {
	if s, found, err := p.getUpload(uploadID); err == nil && found {
		maxChunks = s.MaxChunks
	}
	for n := 0; n < maxChunks; n++ {
		if appErr := p.API.KVDelete(chunkKey(uploadID, n)); appErr != nil {
			return appErr
		}
	}
	if appErr := p.API.KVDelete(keyPrefixUpload + uploadID); appErr != nil {
		return appErr
	}
	p.uploadLocks.Delete(uploadID)
	return nil
}

// listKeys returns every key with the prefix, read in full before the caller deletes any.
func (p *Plugin) listKeys(prefix string) ([]string, error) {
	var all []string
	for page := 0; ; page++ {
		keys, err := p.client.KV.ListKeys(page, 200, pluginapi.WithPrefix(prefix))
		if err != nil {
			return nil, err
		}
		all = append(all, keys...)
		if len(keys) < 200 {
			return all, nil
		}
	}
}

// listUploads reads every upload session, open and attached.
func (p *Plugin) listUploads() ([]*uploadSession, error) {
	keys, err := p.listKeys(keyPrefixUpload)
	if err != nil {
		return nil, err
	}
	out := make([]*uploadSession, 0, len(keys))
	for _, k := range keys {
		s, found, err := p.getUpload(strings.TrimPrefix(k, keyPrefixUpload))
		if err != nil {
			return nil, err
		}
		if found {
			out = append(out, s)
		}
	}
	return out, nil
}

// maxFileBytes returns the server's FileSettings.MaxFileSize, the one source of the file secret limit.
// A missing or non-positive value refuses file secrets instead of guessing a limit.
func (p *Plugin) maxFileBytes() (int64, error) {
	cfg := p.API.GetConfig()
	if cfg == nil || cfg.FileSettings.MaxFileSize == nil || *cfg.FileSettings.MaxFileSize <= 0 {
		return 0, newStatusError(http.StatusServiceUnavailable, "File secrets are unavailable: set Maximum File Size in System Console > File Storage.")
	}
	return *cfg.FileSettings.MaxFileSize, nil
}

// checkFileSender refuses users the FileSecretSenders setting does not allow to send files.
// It is the one check every file entry point (session create, attach, recipients) calls.
func (p *Plugin) checkFileSender(userID string) error {
	switch p.getConfiguration().fileSenders() {
	case sendersNobody:
		return newStatusError(http.StatusForbidden, "File secrets are turned off on this server.")
	case sendersBots:
		u, appErr := p.API.GetUser(userID)
		if appErr != nil || !u.IsBot {
			return newStatusError(http.StatusForbidden, "Only bots can send file secrets on this server.")
		}
	}
	return nil
}

// takeUploadSlot records a new upload for the user, refusing more than maxUploadsPerHour.
func (p *Plugin) takeUploadSlot(userID string, now time.Time) error {
	cutoff := now.Add(-time.Hour).UnixMilli()
	return p.client.KV.SetAtomicWithRetries(keyPrefixUploadRate+userID, func(old []byte) (any, error) {
		var times []int64
		if len(old) > 0 {
			if err := json.Unmarshal(old, &times); err != nil {
				return nil, err
			}
		}
		recent := times[:0]
		for _, t := range times {
			if t > cutoff {
				recent = append(recent, t)
			}
		}
		if len(recent) >= maxUploadsPerHour {
			return nil, errUploadRateLimited
		}
		return json.Marshal(append(recent, now.UnixMilli()))
	})
}

// createUpload opens an upload session after checking the sender, channel, size, quotas and rate.
func (p *Plugin) createUpload(userID, channelID string, maxBytes int64) (*uploadSession, error) {
	conf := p.getConfiguration()
	if err := p.checkFileSender(userID); err != nil {
		return nil, err
	}
	if _, err := p.channelRecipients(channelID, userID); err != nil {
		return nil, newStatusError(http.StatusForbidden, err.Error())
	}
	if maxBytes <= 0 {
		return nil, newStatusError(http.StatusBadRequest, "max_bytes must be positive")
	}
	maxFile, err := p.maxFileBytes()
	if err != nil {
		return nil, err
	}
	if maxBytes > maxFile+fileSlackBytes {
		return nil, newStatusError(http.StatusRequestEntityTooLarge, fmt.Sprintf("Files can be at most %d MB.", maxFile/bytesPerMB))
	}
	maxChunks := int((maxBytes + fileChunkBytes - 1) / fileChunkBytes)
	if maxChunks > maxChunkIndex+1 {
		return nil, newStatusError(http.StatusRequestEntityTooLarge, "File is too large.")
	}

	p.uploadsLock.Lock()
	defer p.uploadsLock.Unlock()
	sessions, err := p.listUploads()
	if err != nil {
		return nil, err
	}
	var userBytes, allBytes int64
	open := 0
	for _, s := range sessions {
		allBytes += s.reservedBytes()
		if s.UserID == userID {
			userBytes += s.reservedBytes()
			if s.State == uploadStateOpen {
				open++
			}
		}
	}
	if open >= maxOpenUploadsPerUser {
		return nil, newStatusError(http.StatusTooManyRequests, "You already have uploads in progress. Finish or cancel them first.")
	}
	if userBytes+maxBytes > 2*maxFile {
		return nil, newStatusError(http.StatusInsufficientStorage, "You have too many unread file secrets. Wait until they are read or expire.")
	}
	if allBytes+maxBytes > conf.maxStorageBytes() {
		return nil, newStatusError(http.StatusInsufficientStorage, "The server's file secret storage is full. Try again later.")
	}
	now := time.Now()
	if err := p.takeUploadSlot(userID, now); err != nil {
		if errors.Is(err, errUploadRateLimited) {
			return nil, newStatusError(http.StatusTooManyRequests, "Too many uploads in the last hour. Try again later.")
		}
		return nil, err
	}
	s := &uploadSession{
		ID:         model.NewId(),
		UserID:     userID,
		ChannelID:  channelID,
		MaxBytes:   maxBytes,
		ChunkSize:  fileChunkBytes,
		MaxChunks:  maxChunks,
		ChunkBytes: make([]int64, maxChunks),
		State:      uploadStateOpen,
		CreatedAt:  now.UnixMilli(),
		ExpiresAt:  now.Add(conf.uploadSession()).UnixMilli(),
	}
	if err := p.setJSON(keyPrefixUpload+s.ID, s); err != nil {
		return nil, err
	}
	return s, nil
}

// handleCreateUpload opens an upload session: POST /uploads {channel_id, max_bytes}.
func (p *Plugin) handleCreateUpload(c *plugin.Context, w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("Mattermost-User-ID")
	audit := plugin.MakeAuditRecordWithContext("secretsCreateUpload", model.AuditStatusFail, c, userID, r.URL.Path)
	defer p.API.LogAuditRec(audit)

	var body struct {
		ChannelID string `json:"channel_id"`
		MaxBytes  int64  `json:"max_bytes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if !model.IsValidId(body.ChannelID) {
		writeError(w, http.StatusBadRequest, "invalid channel_id")
		return
	}
	model.AddEventParameterToAuditRec(audit, "channel_id", body.ChannelID)
	model.AddEventParameterToAuditRec(audit, "max_bytes", body.MaxBytes)
	s, err := p.createUpload(userID, body.ChannelID, body.MaxBytes)
	if err != nil {
		p.writeStatusError(w, err, "failed to start upload")
		return
	}
	model.AddEventParameterToAuditRec(audit, "upload_id", s.ID)
	audit.Success()
	writeJSON(w, http.StatusCreated, map[string]any{
		"upload_id":  s.ID,
		"chunk_size": s.ChunkSize,
		"max_chunks": s.MaxChunks,
		"expires_at": s.ExpiresAt,
	})
}

// openOwnUpload loads an upload the caller owns and can still write to.
// Another user's upload reads as not found so upload IDs cannot be probed.
func (p *Plugin) openOwnUpload(uploadID, userID string) (*uploadSession, error) {
	s, found, err := p.getUpload(uploadID)
	if err != nil {
		return nil, err
	}
	if !found || s.UserID != userID {
		return nil, newStatusError(http.StatusNotFound, "upload not found")
	}
	if s.State != uploadStateOpen || s.ExpiresAt <= time.Now().UnixMilli() {
		return nil, newStatusError(http.StatusConflict, "This upload is closed. Start the upload again.")
	}
	return s, nil
}

// handlePutChunk stores one encrypted chunk: PUT /uploads/{id}/chunks/{n}. Re-sending a chunk replaces it.
func (p *Plugin) handlePutChunk(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("Mattermost-User-ID")
	uploadID := mux.Vars(r)["upload_id"]
	n, err := strconv.Atoi(mux.Vars(r)["n"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid chunk index")
		return
	}
	unlock := p.lockUpload(uploadID)
	defer unlock()
	s, err := p.openOwnUpload(uploadID, userID)
	if err != nil {
		p.writeStatusError(w, err, "failed to read upload")
		return
	}
	if n >= s.MaxChunks {
		writeError(w, http.StatusBadRequest, "chunk index out of range")
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.ChunkSize+chunkTagBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "chunk too large")
		return
	}
	if len(data) <= chunkTagBytes {
		writeError(w, http.StatusBadRequest, "chunk too short")
		return
	}
	if appErr := p.API.KVSet(chunkKey(uploadID, n), data); appErr != nil {
		p.writeStatusError(w, appErr, "failed to store chunk")
		return
	}
	err = p.updateUpload(uploadID, func(cur *uploadSession) error {
		if n >= len(cur.ChunkBytes) {
			return errors.New("chunk index out of range")
		}
		cur.BytesReceived += int64(len(data)) - cur.ChunkBytes[n]
		cur.ChunkBytes[n] = int64(len(data))
		return nil
	})
	if err != nil {
		_ = p.API.KVDelete(chunkKey(uploadID, n))
		p.writeStatusError(w, err, "failed to record chunk")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"received": n})
}

// handleDeleteUpload cancels an unfinished upload: DELETE /uploads/{id}.
func (p *Plugin) handleDeleteUpload(c *plugin.Context, w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("Mattermost-User-ID")
	uploadID := mux.Vars(r)["upload_id"]
	audit := plugin.MakeAuditRecordWithContext("secretsDeleteUpload", model.AuditStatusFail, c, userID, r.URL.Path)
	defer p.API.LogAuditRec(audit)
	model.AddEventParameterToAuditRec(audit, "upload_id", uploadID)

	unlock := p.lockUpload(uploadID)
	defer unlock()
	s, err := p.openOwnUpload(uploadID, userID)
	if err != nil {
		p.writeStatusError(w, err, "failed to read upload")
		return
	}
	if err := p.deleteUpload(uploadID, s.MaxChunks); err != nil {
		p.writeStatusError(w, err, "failed to delete upload")
		return
	}
	audit.Success()
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// validateAttach checks that an upload is complete and matches what the sender declares.
// It exists so a secret never points at missing, extra or mis-sized chunks.
func validateAttach(s *uploadSession, found bool, senderID, channelID string, ref fileRef, now time.Time) error {
	if !found || s.UserID != senderID {
		return newStatusError(http.StatusNotFound, "upload not found")
	}
	if s.ChannelID != channelID {
		return newStatusError(http.StatusBadRequest, "the upload belongs to another channel")
	}
	if s.State != uploadStateOpen || s.ExpiresAt <= now.UnixMilli() {
		return newStatusError(http.StatusConflict, "This upload is closed. Start the upload again.")
	}
	if ref.Bytes <= 0 || ref.Bytes > s.MaxBytes {
		return newStatusError(http.StatusBadRequest, "file size is out of range")
	}
	chunks := int((ref.Bytes + s.ChunkSize - 1) / s.ChunkSize)
	if ref.Chunks != chunks || chunks > len(s.ChunkBytes) {
		return newStatusError(http.StatusBadRequest, "chunk count does not match the file size")
	}
	for i, got := range s.ChunkBytes {
		want := int64(0)
		switch {
		case i < chunks-1:
			want = s.ChunkSize + chunkTagBytes
		case i == chunks-1:
			want = ref.Bytes - int64(chunks-1)*s.ChunkSize + chunkTagBytes
		}
		if got != want {
			return newStatusError(http.StatusBadRequest, fmt.Sprintf("chunk %d is missing or the wrong size", i))
		}
	}
	return nil
}
