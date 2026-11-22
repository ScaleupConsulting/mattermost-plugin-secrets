package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startUpload opens an upload as userID and returns its ID, failing the test otherwise.
func startUpload(t *testing.T, p *Plugin, userID, channelID string, maxBytes int64) string {
	t.Helper()
	rec := do(p, userID, http.MethodPost, "/uploads", mustJSON(t, map[string]any{"channel_id": channelID, "max_bytes": maxBytes}))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var out struct {
		UploadID  string `json:"upload_id"`
		ChunkSize int64  `json:"chunk_size"`
		MaxChunks int    `json:"max_chunks"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.Equal(t, int64(fileChunkBytes), out.ChunkSize)
	require.Equal(t, int((maxBytes+fileChunkBytes-1)/fileChunkBytes), out.MaxChunks)
	return out.UploadID
}

// putChunk uploads a chunk of the given stored length.
func putChunk(p *Plugin, userID, uploadID string, n, length int) int {
	return do(p, userID, http.MethodPut, fmt.Sprintf("/uploads/%s/chunks/%d", uploadID, n), bytes.Repeat([]byte{byte(n)}, length)).Code
}

// uploadFile uploads every chunk of a plaintext file of the given size.
func uploadFile(t *testing.T, p *Plugin, userID, uploadID string, size int64) int {
	t.Helper()
	chunks := int((size + fileChunkBytes - 1) / fileChunkBytes)
	for n := range chunks {
		plain := int64(fileChunkBytes)
		if n == chunks-1 {
			plain = size - int64(n)*fileChunkBytes
		}
		require.Equal(t, http.StatusOK, putChunk(p, userID, uploadID, n, int(plain)+chunkTagBytes))
	}
	return chunks
}

// testEnvelope builds a structurally valid envelope for the recipient's registered key.
func testEnvelope(t *testing.T, p *Plugin, recipient string) envelope {
	t.Helper()
	var rec publicKeyRecord
	found, err := p.getJSON(keyPrefixPubKey+recipient, &rec)
	require.NoError(t, err)
	require.True(t, found)
	return envelope{
		KeyID:      rec.KeyID,
		EphemeralK: base64.StdEncoding.EncodeToString(append([]byte{4}, make([]byte, 64)...)),
		IV:         base64.StdEncoding.EncodeToString(make([]byte, 12)),
		Ciphertext: base64.StdEncoding.EncodeToString([]byte("ciphertext")),
	}
}

// sendFileSecret creates a secret that attaches the upload and returns the post ID.
func sendFileSecret(t *testing.T, p *Plugin, w testWorld, uploadID string, chunks int, size int64) *httptestResult {
	t.Helper()
	rec := do(p, w.sender, http.MethodPost, "/secrets", mustJSON(t, map[string]any{
		"channel_id": w.dm,
		"envelopes":  map[string]envelope{w.recipient: testEnvelope(t, p, w.recipient)},
		"file":       fileRef{UploadID: uploadID, Chunks: chunks, Bytes: size},
	}))
	var out struct {
		PostID string `json:"post_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return &httptestResult{code: rec.Code, body: rec.Body.String(), postID: out.PostID}
}

// notRouted is what the router answers for a method a path does not accept.
var notRouted = []int{http.StatusNotFound, http.StatusMethodNotAllowed}

// httptestResult is the parts of a create-secret response the tests check.
type httptestResult struct {
	code   int
	body   string
	postID string
}

func TestValidateAttach(t *testing.T) {
	const cs = fileChunkBytes
	sender, channel := model.NewId(), model.NewId()
	now := time.Now()
	base := func() *uploadSession {
		return &uploadSession{
			UserID: sender, ChannelID: channel, MaxBytes: 2*cs + 100, ChunkSize: cs, MaxChunks: 3,
			ChunkBytes: []int64{cs + chunkTagBytes, cs + chunkTagBytes, 100 + chunkTagBytes},
			State:      uploadStateOpen, ExpiresAt: now.Add(time.Hour).UnixMilli(),
		}
	}
	good := fileRef{Chunks: 3, Bytes: 2*cs + 100}
	tests := []struct {
		name   string
		mutate func(s *uploadSession, ref *fileRef) (found bool, senderID, channelID string)
		status int
	}{
		{"complete upload", func(*uploadSession, *fileRef) (bool, string, string) { return true, sender, channel }, 0},
		{"missing session", func(*uploadSession, *fileRef) (bool, string, string) { return false, sender, channel }, http.StatusNotFound},
		{"another user's upload", func(*uploadSession, *fileRef) (bool, string, string) { return true, model.NewId(), channel }, http.StatusNotFound},
		{"another channel", func(*uploadSession, *fileRef) (bool, string, string) { return true, sender, model.NewId() }, http.StatusBadRequest},
		{"already attached", func(s *uploadSession, _ *fileRef) (bool, string, string) {
			s.State = uploadStateAttached
			return true, sender, channel
		}, http.StatusConflict},
		{"expired", func(s *uploadSession, _ *fileRef) (bool, string, string) {
			s.ExpiresAt = now.Add(-time.Second).UnixMilli()
			return true, sender, channel
		}, http.StatusConflict},
		{"zero bytes", func(_ *uploadSession, r *fileRef) (bool, string, string) {
			r.Bytes = 0
			return true, sender, channel
		}, http.StatusBadRequest},
		{"bytes over the reservation", func(s *uploadSession, _ *fileRef) (bool, string, string) {
			s.MaxBytes = 2 * cs
			return true, sender, channel
		}, http.StatusBadRequest},
		{"chunk count disagrees with size", func(_ *uploadSession, r *fileRef) (bool, string, string) {
			r.Chunks = 2
			return true, sender, channel
		}, http.StatusBadRequest},
		{"missing middle chunk", func(s *uploadSession, _ *fileRef) (bool, string, string) {
			s.ChunkBytes[1] = 0
			return true, sender, channel
		}, http.StatusBadRequest},
		{"short middle chunk", func(s *uploadSession, _ *fileRef) (bool, string, string) {
			s.ChunkBytes[0] = cs
			return true, sender, channel
		}, http.StatusBadRequest},
		{"last chunk size disagrees with bytes", func(_ *uploadSession, r *fileRef) (bool, string, string) {
			r.Bytes = 2*cs + 99
			return true, sender, channel
		}, http.StatusBadRequest},
		{"extra chunk past the end", func(s *uploadSession, r *fileRef) (bool, string, string) {
			s.ChunkBytes = append(s.ChunkBytes, 50)
			return true, sender, channel
		}, http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, ref := base(), good
			found, senderID, channelID := tc.mutate(s, &ref)
			err := validateAttach(s, found, senderID, channelID, ref, now)
			if tc.status == 0 {
				require.NoError(t, err)
				return
			}
			var se *statusError
			require.ErrorAs(t, err, &se)
			assert.Equal(t, tc.status, se.status)
		})
	}
}

func TestCreateUpload(t *testing.T) {
	const mb = bytesPerMB
	t.Run("requires a session", func(t *testing.T) {
		p, _, w := newTestPlugin(t, nil)
		rec := do(p, "", http.MethodPost, "/uploads", mustJSON(t, map[string]any{"channel_id": w.dm, "max_bytes": 10}))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
	t.Run("GET is not routed", func(t *testing.T) {
		p, _, w := newTestPlugin(t, nil)
		assert.Contains(t, notRouted, do(p, w.sender, http.MethodGet, "/uploads", nil).Code)
	})
	denied := []struct {
		name    string
		conf    *configuration
		user    func(w testWorld) string
		channel func(w testWorld) string
		bytes   int64
		status  int
	}{
		{"non-member", nil, func(w testWorld) string { return w.outsider }, func(w testWorld) string { return w.dm }, 10, http.StatusForbidden},
		{"not a DM", nil, func(w testWorld) string { return w.sender }, func(w testWorld) string { return w.openChannel }, 10, http.StatusForbidden},
		{"file secrets off", &configuration{FileSecretSenders: sendersNobody}, func(w testWorld) string { return w.sender }, func(w testWorld) string { return w.dm }, 10, http.StatusForbidden},
		{"bots only, human sender", &configuration{FileSecretSenders: sendersBots}, func(w testWorld) string { return w.sender }, func(w testWorld) string { return w.dm }, 10, http.StatusForbidden},
		{"over the file limit", &configuration{MaxFileSizeMB: 1}, func(w testWorld) string { return w.sender }, func(w testWorld) string { return w.dm }, mb + fileSlackBytes + 1, http.StatusRequestEntityTooLarge},
		{"zero bytes", nil, func(w testWorld) string { return w.sender }, func(w testWorld) string { return w.dm }, 0, http.StatusBadRequest},
	}
	for _, tc := range denied {
		t.Run(tc.name, func(t *testing.T) {
			p, f, w := newTestPlugin(t, tc.conf)
			rec := do(p, tc.user(w), http.MethodPost, "/uploads", mustJSON(t, map[string]any{"channel_id": tc.channel(w), "max_bytes": tc.bytes}))
			assert.Equal(t, tc.status, rec.Code, rec.Body.String())
			assert.Empty(t, f.keysWithPrefix(keyPrefixUpload))
		})
	}
	t.Run("bots only, bot sender", func(t *testing.T) {
		p, _, w := newTestPlugin(t, &configuration{FileSecretSenders: sendersBots})
		startUpload(t, p, w.bot, w.botDM, 10)
	})
	t.Run("PGP slack over the limit is allowed", func(t *testing.T) {
		p, _, w := newTestPlugin(t, &configuration{MaxFileSizeMB: 1})
		startUpload(t, p, w.sender, w.dm, mb+fileSlackBytes)
	})
	t.Run("audit record names the upload", func(t *testing.T) {
		p, f, w := newTestPlugin(t, nil)
		id := startUpload(t, p, w.sender, w.dm, 10)
		require.Len(t, f.audits, 1)
		assert.Equal(t, model.AuditStatusSuccess, f.audits[0].Status)
		assert.Equal(t, id, f.audits[0].EventData.Parameters["upload_id"])
	})
	t.Run("at most two open uploads", func(t *testing.T) {
		p, _, w := newTestPlugin(t, nil)
		startUpload(t, p, w.sender, w.dm, 10)
		startUpload(t, p, w.sender, w.dm, 10)
		rec := do(p, w.sender, http.MethodPost, "/uploads", mustJSON(t, map[string]any{"channel_id": w.dm, "max_bytes": 10}))
		assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	})
	t.Run("per-user storage is twice the file limit", func(t *testing.T) {
		p, _, w := newTestPlugin(t, &configuration{MaxFileSizeMB: 1})
		startUpload(t, p, w.sender, w.dm, mb)
		rec := do(p, w.sender, http.MethodPost, "/uploads", mustJSON(t, map[string]any{"channel_id": w.dm, "max_bytes": mb + 1}))
		assert.Equal(t, http.StatusInsufficientStorage, rec.Code)
		startUpload(t, p, w.sender, w.dm, mb)
	})
	t.Run("global storage cap", func(t *testing.T) {
		p, _, w := newTestPlugin(t, &configuration{MaxFileSizeMB: 2, MaxStorageMB: 3})
		startUpload(t, p, w.sender, w.dm, 2*mb)
		rec := do(p, w.bot, http.MethodPost, "/uploads", mustJSON(t, map[string]any{"channel_id": w.botDM, "max_bytes": mb + 1}))
		assert.Equal(t, http.StatusInsufficientStorage, rec.Code)
	})
	t.Run("ten uploads an hour", func(t *testing.T) {
		p, _, w := newTestPlugin(t, nil)
		for range maxUploadsPerHour {
			id := startUpload(t, p, w.sender, w.dm, 10)
			require.Equal(t, http.StatusOK, do(p, w.sender, http.MethodDelete, "/uploads/"+id, nil).Code)
		}
		rec := do(p, w.sender, http.MethodPost, "/uploads", mustJSON(t, map[string]any{"channel_id": w.dm, "max_bytes": 10}))
		assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	})
}

func TestPutChunk(t *testing.T) {
	p, f, w := newTestPlugin(t, nil)
	id := startUpload(t, p, w.sender, w.dm, fileChunkBytes+10)

	t.Run("requires a session", func(t *testing.T) {
		assert.Equal(t, http.StatusUnauthorized, putChunk(p, "", id, 0, 100))
	})
	t.Run("another user's upload reads as not found", func(t *testing.T) {
		assert.Equal(t, http.StatusNotFound, putChunk(p, w.recipient, id, 0, 100))
	})
	t.Run("POST is not routed", func(t *testing.T) {
		rec := do(p, w.sender, http.MethodPost, "/uploads/"+id+"/chunks/0", []byte("x"))
		assert.Contains(t, notRouted, rec.Code)
	})
	t.Run("index past max_chunks", func(t *testing.T) {
		assert.Equal(t, http.StatusBadRequest, putChunk(p, w.sender, id, 2, 100))
	})
	t.Run("too large", func(t *testing.T) {
		assert.Equal(t, http.StatusRequestEntityTooLarge, putChunk(p, w.sender, id, 0, fileChunkBytes+chunkTagBytes+1))
	})
	t.Run("too short", func(t *testing.T) {
		assert.Equal(t, http.StatusBadRequest, putChunk(p, w.sender, id, 0, chunkTagBytes))
	})
	t.Run("re-sending a chunk replaces it", func(t *testing.T) {
		require.Equal(t, http.StatusOK, putChunk(p, w.sender, id, 1, 100))
		require.Equal(t, http.StatusOK, putChunk(p, w.sender, id, 1, 10+chunkTagBytes))
		s, found, err := p.getUpload(id)
		require.NoError(t, err)
		require.True(t, found)
		assert.Equal(t, []int64{0, 10 + chunkTagBytes}, s.ChunkBytes)
		assert.Equal(t, int64(10+chunkTagBytes), s.BytesReceived)
		assert.Len(t, f.kv[chunkKey(id, 1)], 10+chunkTagBytes)
	})
	t.Run("expired upload is closed", func(t *testing.T) {
		require.NoError(t, p.updateUpload(id, func(s *uploadSession) error {
			s.ExpiresAt = time.Now().Add(-time.Second).UnixMilli()
			return nil
		}))
		assert.Equal(t, http.StatusConflict, putChunk(p, w.sender, id, 0, 100))
	})
}

func TestDeleteUpload(t *testing.T) {
	p, f, w := newTestPlugin(t, nil)
	id := startUpload(t, p, w.sender, w.dm, 2*fileChunkBytes)
	require.Equal(t, http.StatusOK, putChunk(p, w.sender, id, 0, 100))

	assert.Equal(t, http.StatusUnauthorized, do(p, "", http.MethodDelete, "/uploads/"+id, nil).Code)
	assert.Equal(t, http.StatusNotFound, do(p, w.recipient, http.MethodDelete, "/uploads/"+id, nil).Code)
	assert.Contains(t, notRouted, do(p, w.sender, http.MethodGet, "/uploads/"+id, nil).Code)
	assert.NotEmpty(t, f.keysWithPrefix(keyPrefixChunk))

	assert.Equal(t, http.StatusOK, do(p, w.sender, http.MethodDelete, "/uploads/"+id, nil).Code)
	assert.Empty(t, f.keysWithPrefix(keyPrefixChunk))
	assert.Empty(t, f.keysWithPrefix(keyPrefixUpload))
	assert.Equal(t, http.StatusNotFound, do(p, w.sender, http.MethodDelete, "/uploads/"+id, nil).Code)
}

func TestFileSecretLifecycle(t *testing.T) {
	const size = fileChunkBytes + 1234
	p, f, w := newTestPlugin(t, nil)
	id := startUpload(t, p, w.sender, w.dm, size+500)
	chunks := uploadFile(t, p, w.sender, id, size)
	require.Equal(t, 2, chunks)

	t.Run("another user cannot attach the upload", func(t *testing.T) {
		pub := testPublicKey(t)
		kid, err := parsePublicKey(pub)
		require.NoError(t, err)
		require.NoError(t, p.setJSON(keyPrefixPubKey+w.sender, publicKeyRecord{PublicKey: pub, KeyID: kid}))
		rec := do(p, w.recipient, http.MethodPost, "/secrets", mustJSON(t, map[string]any{
			"channel_id": w.dm,
			"envelopes":  map[string]envelope{w.sender: testEnvelope(t, p, w.sender)},
			"file":       fileRef{UploadID: id, Chunks: chunks, Bytes: size},
		}))
		assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	})
	t.Run("a wrong size is refused", func(t *testing.T) {
		res := sendFileSecret(t, p, w, id, chunks, size-1)
		assert.Equal(t, http.StatusBadRequest, res.code, res.body)
	})

	res := sendFileSecret(t, p, w, id, chunks, size)
	require.Equal(t, http.StatusCreated, res.code, res.body)
	post := f.posts[res.postID]
	require.NotNil(t, post)
	assert.EqualValues(t, 2, post.GetProp(propVersion))
	assert.EqualValues(t, size, post.GetProp(propFileBytes))
	s, _, err := p.getUpload(id)
	require.NoError(t, err)
	assert.Equal(t, uploadStateAttached, s.State)
	assert.Equal(t, res.postID, s.PostID)

	t.Run("chunks can no longer be changed", func(t *testing.T) {
		assert.Equal(t, http.StatusConflict, putChunk(p, w.sender, id, 0, 100))
		assert.Equal(t, http.StatusConflict, do(p, w.sender, http.MethodDelete, "/uploads/"+id, nil).Code)
	})

	chunkPath := func(n int) string { return fmt.Sprintf("/secrets/%s/file/%d", res.postID, n) }
	t.Run("download is refused to everyone but a remaining recipient", func(t *testing.T) {
		assert.Equal(t, http.StatusUnauthorized, do(p, "", http.MethodGet, chunkPath(0), nil).Code)
		assert.Equal(t, http.StatusForbidden, do(p, w.outsider, http.MethodGet, chunkPath(0), nil).Code)
		assert.Equal(t, http.StatusForbidden, do(p, w.sender, http.MethodGet, chunkPath(0), nil).Code)
		assert.Equal(t, http.StatusNotFound, do(p, w.recipient, http.MethodGet, chunkPath(2), nil).Code)
		assert.Equal(t, http.StatusNotFound, do(p, w.recipient, http.MethodGet, fmt.Sprintf("/secrets/%s/file/0", model.NewId()), nil).Code)
	})
	t.Run("recipient downloads every chunk without burning it", func(t *testing.T) {
		for n := range chunks {
			rec := do(p, w.recipient, http.MethodGet, chunkPath(n), nil)
			require.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, "application/octet-stream", rec.Header().Get("Content-Type"))
			assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
			assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
			assert.Equal(t, f.kv[chunkKey(id, n)], rec.Body.Bytes())
		}
		assert.Equal(t, http.StatusOK, do(p, w.recipient, http.MethodGet, chunkPath(0), nil).Code)
	})
	t.Run("the last ack burns the chunks and the session", func(t *testing.T) {
		require.Equal(t, http.StatusOK, do(p, w.recipient, http.MethodPost, "/secrets/"+res.postID+"/ack", []byte("{}")).Code)
		assert.Empty(t, f.keysWithPrefix(keyPrefixChunk))
		assert.Empty(t, f.keysWithPrefix(keyPrefixUpload))
		assert.Equal(t, true, f.posts[res.postID].GetProp(propBurned))
		assert.Equal(t, http.StatusGone, do(p, w.recipient, http.MethodGet, chunkPath(0), nil).Code)
	})
}

func TestFileSecretCleanup(t *testing.T) {
	setup := func(t *testing.T) (*Plugin, *fakeServer, testWorld, string) {
		p, f, w := newTestPlugin(t, nil)
		id := startUpload(t, p, w.sender, w.dm, 100)
		chunks := uploadFile(t, p, w.sender, id, 100)
		res := sendFileSecret(t, p, w, id, chunks, 100)
		require.Equal(t, http.StatusCreated, res.code, res.body)
		return p, f, w, res.postID
	}
	t.Run("deleting the post purges the file", func(t *testing.T) {
		p, f, _, postID := setup(t)
		p.MessageHasBeenDeleted(&plugin.Context{}, f.posts[postID])
		assert.Empty(t, f.keysWithPrefix(keyPrefixChunk))
		assert.Empty(t, f.keysWithPrefix(keyPrefixUpload))
		assert.Empty(t, f.keysWithPrefix(keyPrefixIndex))
	})
	t.Run("expiry sweep burns the file", func(t *testing.T) {
		p, f, _, postID := setup(t)
		var idx secretIndex
		_, err := p.getJSON(keyPrefixIndex+postID, &idx)
		require.NoError(t, err)
		idx.ExpiresAt = time.Now().Add(-time.Second).UnixMilli()
		require.NoError(t, p.setJSON(keyPrefixIndex+postID, idx))
		p.sweepExpired()
		assert.Empty(t, f.keysWithPrefix(keyPrefixChunk))
		assert.Empty(t, f.keysWithPrefix(keyPrefixUpload))
		assert.Equal(t, true, f.posts[postID].GetProp(propBurned))
	})
	t.Run("sweep deletes an attached upload whose index is gone", func(t *testing.T) {
		p, f, _, postID := setup(t)
		delete(f.kv, keyPrefixIndex+postID)
		p.sweepExpired()
		assert.Empty(t, f.keysWithPrefix(keyPrefixChunk))
		assert.Empty(t, f.keysWithPrefix(keyPrefixUpload))
	})
	t.Run("sweep keeps a live upload and deletes an expired one", func(t *testing.T) {
		p, f, w := newTestPlugin(t, nil)
		live := startUpload(t, p, w.sender, w.dm, 100)
		stale := startUpload(t, p, w.sender, w.dm, 100)
		require.Equal(t, http.StatusOK, putChunk(p, w.sender, stale, 0, 50))
		require.NoError(t, p.updateUpload(stale, func(s *uploadSession) error {
			s.ExpiresAt = time.Now().Add(-time.Second).UnixMilli()
			return nil
		}))
		p.sweepExpired()
		assert.Equal(t, []string{keyPrefixUpload + live}, f.keysWithPrefix(keyPrefixUpload))
		assert.Empty(t, f.keysWithPrefix(keyPrefixChunk))
	})
}

func TestRecipientsReportsFileLimits(t *testing.T) {
	tests := []struct {
		name      string
		conf      *configuration
		isEnabled bool
	}{
		{"everyone", &configuration{MaxFileSizeMB: 5}, true},
		{"bots only", &configuration{MaxFileSizeMB: 5, FileSecretSenders: sendersBots}, false},
		{"nobody", &configuration{MaxFileSizeMB: 5, FileSecretSenders: sendersNobody}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, _, w := newTestPlugin(t, tc.conf)
			rec := do(p, w.sender, http.MethodGet, "/channels/"+w.dm+"/recipients", nil)
			require.Equal(t, http.StatusOK, rec.Code)
			var out struct {
				Enabled bool  `json:"file_secrets_enabled"`
				Max     int64 `json:"max_file_bytes"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
			assert.Equal(t, tc.isEnabled, out.Enabled)
			assert.Equal(t, int64(5*bytesPerMB), out.Max)
		})
	}
}

func TestTextSecretStaysVersionOne(t *testing.T) {
	p, f, w := newTestPlugin(t, nil)
	rec := do(p, w.sender, http.MethodPost, "/secrets", mustJSON(t, map[string]any{
		"channel_id": w.dm,
		"envelopes":  map[string]envelope{w.recipient: testEnvelope(t, p, w.recipient)},
	}))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var out struct {
		PostID string `json:"post_id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	assert.EqualValues(t, 1, f.posts[out.PostID].GetProp(propVersion))
	assert.Nil(t, f.posts[out.PostID].GetProp(propFileBytes))
	assert.Empty(t, f.audits)
}
