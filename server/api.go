package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/mattermost/mattermost/server/public/plugin"
)

// ServeHTTP routes the plugin's REST API; every route requires a logged-in user.
func (p *Plugin) ServeHTTP(_ *plugin.Context, w http.ResponseWriter, r *http.Request) {
	router := mux.NewRouter()
	router.Use(requireUser)
	api := router.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/keys", p.handleRegisterKey).Methods(http.MethodPost)
	api.HandleFunc("/keys/me", p.handleGetMyKey).Methods(http.MethodGet)
	api.HandleFunc("/channels/{channel_id:[a-z0-9]{26}}/recipients", p.handleRecipients).Methods(http.MethodGet)
	api.HandleFunc("/secrets", p.handleCreateSecret).Methods(http.MethodPost)
	api.HandleFunc("/secrets/{post_id:[a-z0-9]{26}}/envelope", p.handleGetEnvelope).Methods(http.MethodGet)
	api.HandleFunc("/secrets/{post_id:[a-z0-9]{26}}/ack", p.handleAck).Methods(http.MethodPost)
	api.HandleFunc("/secrets/{post_id:[a-z0-9]{26}}/status", p.handleStatus).Methods(http.MethodGet)
	router.ServeHTTP(w, r)
}

// requireUser rejects requests the server did not authenticate as a user.
func requireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Mattermost-User-ID") == "" {
			writeError(w, http.StatusUnauthorized, "not logged in")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// writeJSON sends v as a JSON response.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError sends {"error": msg}, the shape the webapp shows to users.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// handleRegisterKey stores the caller's browser-generated public key, replacing any earlier one.
func (p *Plugin) handleRegisterKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	kid, err := parsePublicKey(body.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	rec := publicKeyRecord{PublicKey: body.PublicKey, KeyID: kid, CreatedAt: time.Now().UnixMilli()}
	if err := p.setJSON(keyPrefixPubKey+r.Header.Get("Mattermost-User-ID"), rec); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store key")
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

// handleGetMyKey returns the caller's registered key so the browser can tell if it is current.
func (p *Plugin) handleGetMyKey(w http.ResponseWriter, r *http.Request) {
	var rec publicKeyRecord
	found, err := p.getJSON(keyPrefixPubKey+r.Header.Get("Mattermost-User-ID"), &rec)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read key")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "no key registered")
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

// recipientInfo is what a sender's browser needs to encrypt for one recipient.
type recipientInfo struct {
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	PublicKey string `json:"public_key,omitempty"`
	KeyID     string `json:"kid,omitempty"`
}

// handleRecipients lists the channel's other members with their keys, and who has no key.
func (p *Plugin) handleRecipients(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("Mattermost-User-ID")
	ids, err := p.channelRecipients(mux.Vars(r)["channel_id"], userID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	recipients := []recipientInfo{}
	missing := []string{}
	for _, uid := range ids {
		info := recipientInfo{UserID: uid, Username: uid}
		if u, appErr := p.API.GetUser(uid); appErr == nil {
			info.Username = u.Username
		}
		var rec publicKeyRecord
		if found, _ := p.getJSON(keyPrefixPubKey+uid, &rec); found {
			info.PublicKey, info.KeyID = rec.PublicKey, rec.KeyID
			recipients = append(recipients, info)
		} else {
			missing = append(missing, info.Username)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"recipients":     recipients,
		"missing":        missing,
		"expiry_minutes": int(p.getConfiguration().expiry() / time.Minute),
	})
}

// handleCreateSecret accepts per-recipient ciphertext from the sender's browser and posts the placeholder.
func (p *Plugin) handleCreateSecret(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ChannelID string              `json:"channel_id"`
		RootID    string              `json:"root_id"`
		Envelopes map[string]envelope `json:"envelopes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxGroupMembers*(maxCiphertextB64+1024))).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	post, err := p.createSecret(r.Header.Get("Mattermost-User-ID"), body.ChannelID, body.RootID, body.Envelopes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"post_id": post.Id})
}

// handleGetEnvelope returns the caller's own ciphertext for a post, or 410 once it is burned.
func (p *Plugin) handleGetEnvelope(w http.ResponseWriter, r *http.Request) {
	var env envelope
	found, err := p.getJSON(envelopeKey(mux.Vars(r)["post_id"], r.Header.Get("Mattermost-User-ID")), &env)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read secret")
		return
	}
	if !found {
		writeError(w, http.StatusGone, "This secret has already been read or has expired.")
		return
	}
	writeJSON(w, http.StatusOK, env)
}

// handleAck deletes the caller's ciphertext after their browser decrypted it.
func (p *Plugin) handleAck(w http.ResponseWriter, r *http.Request) {
	if err := p.ackSecret(mux.Vars(r)["post_id"], r.Header.Get("Mattermost-User-ID")); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to burn secret")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "burned"})
}

// handleStatus tells channel members which recipients have not read a secret yet.
func (p *Plugin) handleStatus(w http.ResponseWriter, r *http.Request) {
	postID := mux.Vars(r)["post_id"]
	post, appErr := p.API.GetPost(postID)
	if appErr != nil || post.Type != PostType {
		writeError(w, http.StatusNotFound, "secret not found")
		return
	}
	if _, appErr := p.API.GetChannelMember(post.ChannelId, r.Header.Get("Mattermost-User-ID")); appErr != nil {
		writeError(w, http.StatusForbidden, "not a member of this channel")
		return
	}
	var idx secretIndex
	found, err := p.getJSON(keyPrefixIndex+postID, &idx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read status")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"burned": !found, "remaining": idx.Remaining, "expires_at": idx.ExpiresAt})
}
