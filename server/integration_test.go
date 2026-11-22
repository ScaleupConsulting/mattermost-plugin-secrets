package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/pluginapi/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFileSecretIntegration runs a two-chunk file secret through a real server: raw 4 MiB KV rows,
// ListKeys on servers without KVListWithOptions, the recipient-only download and burn on ack.
func TestFileSecretIntegration(t *testing.T) {
	th := testhelper.Setup(t)
	ctx := t.Context()
	recipient := th.CreateUser()
	rc := model.NewAPIv4Client(th.ServerURL)
	_, _, err := rc.Login(ctx, recipient.Username, "Password1!")
	require.NoError(t, err)
	dm, _, err := th.Client.CreateDirectChannel(ctx, th.User.Id, recipient.Id)
	require.NoError(t, err)

	base := th.ServerURL + "/plugins/" + testhelper.PluginID() + "/api/v1"
	call := func(c *model.Client4, method, path string, body []byte) (int, []byte) {
		req, reqErr := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(body))
		require.NoError(t, reqErr)
		if c != nil {
			req.Header.Set("Authorization", "Bearer "+c.AuthToken)
		}
		resp, doErr := http.DefaultClient.Do(req)
		require.NoError(t, doErr)
		defer func() { _ = resp.Body.Close() }()
		out, readErr := io.ReadAll(resp.Body)
		require.NoError(t, readErr)
		return resp.StatusCode, out
	}

	pub := testPublicKey(t)
	code, out := call(rc, http.MethodPost, "/keys", mustJSON(t, map[string]string{"public_key": pub}))
	require.Equal(t, http.StatusOK, code, string(out))
	var key publicKeyRecord
	require.NoError(t, json.Unmarshal(out, &key))

	code, out = call(th.Client, http.MethodGet, "/channels/"+dm.Id+"/recipients", nil)
	require.Equal(t, http.StatusOK, code, string(out))
	assert.Contains(t, string(out), `"file_secrets_enabled":true`)

	const size = fileChunkBytes + 10
	code, _ = call(nil, http.MethodPost, "/uploads", mustJSON(t, map[string]any{"channel_id": dm.Id, "max_bytes": size}))
	assert.Equal(t, http.StatusUnauthorized, code)
	code, _ = call(th.Client, http.MethodPost, "/uploads", mustJSON(t, map[string]any{"channel_id": th.Channel.Id, "max_bytes": size}))
	assert.Equal(t, http.StatusForbidden, code)

	code, out = call(th.Client, http.MethodPost, "/uploads", mustJSON(t, map[string]any{"channel_id": dm.Id, "max_bytes": size}))
	require.Equal(t, http.StatusCreated, code, string(out))
	var up struct {
		UploadID string `json:"upload_id"`
	}
	require.NoError(t, json.Unmarshal(out, &up))

	chunks := [][]byte{make([]byte, fileChunkBytes+chunkTagBytes), make([]byte, 10+chunkTagBytes)}
	for n, c := range chunks {
		_, randErr := rand.Read(c)
		require.NoError(t, randErr)
		code, _ = call(rc, http.MethodPut, fmt.Sprintf("/uploads/%s/chunks/%d", up.UploadID, n), c)
		assert.Equal(t, http.StatusNotFound, code, "another user's upload")
		code, out = call(th.Client, http.MethodPut, fmt.Sprintf("/uploads/%s/chunks/%d", up.UploadID, n), c)
		require.Equal(t, http.StatusOK, code, string(out))
	}

	env := envelope{
		KeyID:      key.KeyID,
		EphemeralK: base64.StdEncoding.EncodeToString(append([]byte{4}, make([]byte, 64)...)),
		IV:         base64.StdEncoding.EncodeToString(make([]byte, 12)),
		Ciphertext: base64.StdEncoding.EncodeToString([]byte("ciphertext")),
	}
	code, out = call(th.Client, http.MethodPost, "/secrets", mustJSON(t, map[string]any{
		"channel_id": dm.Id,
		"envelopes":  map[string]envelope{recipient.Id: env},
		"file":       fileRef{UploadID: up.UploadID, Chunks: 2, Bytes: size},
	}))
	require.Equal(t, http.StatusCreated, code, string(out))
	var created struct {
		PostID string `json:"post_id"`
	}
	require.NoError(t, json.Unmarshal(out, &created))
	post, _, err := rc.GetPost(ctx, created.PostID, "")
	require.NoError(t, err)
	assert.EqualValues(t, 2, post.GetProp(propVersion))
	assert.EqualValues(t, size, post.GetProp(propFileBytes))

	chunkPath := func(n int) string { return fmt.Sprintf("/secrets/%s/file/%d", created.PostID, n) }
	code, _ = call(th.Client, http.MethodGet, chunkPath(0), nil)
	assert.Equal(t, http.StatusForbidden, code, "the sender is not a recipient")
	for n, c := range chunks {
		code, out = call(rc, http.MethodGet, chunkPath(n), nil)
		require.Equal(t, http.StatusOK, code)
		assert.Equal(t, c, out)
	}

	code, _ = call(rc, http.MethodPost, "/secrets/"+created.PostID+"/ack", []byte("{}"))
	require.Equal(t, http.StatusOK, code)
	code, _ = call(rc, http.MethodGet, chunkPath(0), nil)
	assert.Equal(t, http.StatusGone, code)

	// The burned upload no longer counts, so the sender can start two more.
	for range maxOpenUploadsPerUser {
		code, out = call(th.Client, http.MethodPost, "/uploads", mustJSON(t, map[string]any{"channel_id": dm.Id, "max_bytes": 10}))
		require.Equal(t, http.StatusCreated, code, string(out))
	}
}
