package main

import (
	"net/http"
	"slices"
	"strconv"

	"github.com/gorilla/mux"
)

// handleGetFileChunk returns one encrypted chunk of a file secret to a recipient who has not read it yet:
// GET /secrets/{post_id}/file/{n}. It never acks; the browser acks after decrypting the whole file.
func (p *Plugin) handleGetFileChunk(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("Mattermost-User-ID")
	postID := mux.Vars(r)["post_id"]
	n, err := strconv.Atoi(mux.Vars(r)["n"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid chunk index")
		return
	}
	post, appErr := p.API.GetPost(postID)
	if appErr != nil || post.Type != PostType {
		writeError(w, http.StatusNotFound, "secret not found")
		return
	}
	if _, memberErr := p.API.GetChannelMember(post.ChannelId, userID); memberErr != nil {
		writeError(w, http.StatusForbidden, "not a member of this channel")
		return
	}
	var idx secretIndex
	found, err := p.getJSON(keyPrefixIndex+postID, &idx)
	if err != nil {
		p.writeStatusError(w, err, "failed to read secret")
		return
	}
	if !found {
		writeError(w, http.StatusGone, "This secret has already been read or has expired.")
		return
	}
	if !slices.Contains(idx.Remaining, userID) {
		writeError(w, http.StatusForbidden, "This secret is not for you, or you have already read it.")
		return
	}
	if idx.UploadID == "" || n >= idx.Chunks {
		writeError(w, http.StatusNotFound, "chunk not found")
		return
	}
	data, appErr := p.API.KVGet(chunkKey(idx.UploadID, n))
	if appErr != nil {
		p.writeStatusError(w, appErr, "failed to read chunk")
		return
	}
	if data == nil {
		writeError(w, http.StatusGone, "This secret has already been read or has expired.")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
