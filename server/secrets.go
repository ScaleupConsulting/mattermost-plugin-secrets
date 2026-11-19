package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/pkg/errors"
)

const (
	// PostType is the custom post type that carries a secret's placeholder and metadata.
	PostType = "custom_secret"

	// Placeholder is the only text a secret post may carry in Message; it never contains the secret.
	Placeholder = "Secret message. Open it in Mattermost on desktop or web to reveal it; the mobile app cannot show secrets."

	propVersion    = "secret_v"
	propRecipients = "secret_recipients"
	propExpiresAt  = "secret_expires_at"
	propNonce      = "secret_nonce"
	propBurned     = "secret_burned"
	propBurnedAt   = "secret_burned_at"

	keyPrefixPubKey   = "pk_"
	keyPrefixEnvelope = "env_"
	keyPrefixIndex    = "idx_"

	// maxCiphertextB64 bounds one envelope; the composer caps plaintext at 4000 characters.
	maxCiphertextB64 = 24000
	maxGroupMembers  = 8
)

// allowedProps lists every prop key a secret post may carry; anything else is rejected.
var allowedProps = map[string]bool{
	propVersion: true, propRecipients: true, propExpiresAt: true, propNonce: true,
	propBurned: true, propBurnedAt: true,
	"from_plugin": true, "disable_group_highlight": true,
	// The server stamps from_bot on every bot post, so bots can send secrets too.
	model.PostPropsFromBot: true,
}

// publicKeyRecord is a user's registered ECDH P-256 public key.
type publicKeyRecord struct {
	PublicKey string `json:"public_key"`
	KeyID     string `json:"kid"`
	CreatedAt int64  `json:"created_at"`
}

// envelope is one recipient's ciphertext: ECIES over P-256 with HKDF-SHA256 and AES-256-GCM.
type envelope struct {
	KeyID      string `json:"kid"`
	EphemeralK string `json:"epk"`
	IV         string `json:"iv"`
	Ciphertext string `json:"ct"`
}

// secretIndex tracks who still holds ciphertext for a secret post and when it expires.
type secretIndex struct {
	PostID    string   `json:"post_id"`
	ChannelID string   `json:"channel_id"`
	SenderID  string   `json:"sender_id"`
	Remaining []string `json:"remaining"`
	ExpiresAt int64    `json:"expires_at"`
}

// envelopeKey names the KV row that holds one recipient's ciphertext for one post.
func envelopeKey(postID, userID string) string {
	return keyPrefixEnvelope + postID + "_" + userID
}

// parsePublicKey checks that b64 is a base64 SPKI P-256 public key and returns its key ID.
// It exists so a malformed key is refused at registration instead of failing in a sender's browser.
func parsePublicKey(b64 string) (string, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", errors.New("public_key is not base64")
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return "", errors.Wrap(err, "public_key is not SPKI")
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return "", errors.New("public_key must be an EC P-256 key")
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:16]), nil
}

// validateEnvelope bounds and decodes an envelope's fields so junk never reaches the KV store.
func validateEnvelope(e envelope) error {
	if len(e.Ciphertext) == 0 || len(e.Ciphertext) > maxCiphertextB64 {
		return errors.New("ciphertext missing or too long")
	}
	for name, v := range map[string]string{"epk": e.EphemeralK, "iv": e.IV, "ct": e.Ciphertext} {
		if _, err := base64.StdEncoding.DecodeString(v); err != nil {
			return fmt.Errorf("%s is not base64", name)
		}
	}
	if raw, _ := base64.StdEncoding.DecodeString(e.EphemeralK); len(raw) != 65 {
		return errors.New("epk must be an uncompressed P-256 point")
	}
	if raw, _ := base64.StdEncoding.DecodeString(e.IV); len(raw) != 12 {
		return errors.New("iv must be 12 bytes")
	}
	return nil
}

// isSecretChannel reports whether a channel is a DM or group DM, the only places secrets may go.
func isSecretChannel(ch *model.Channel) bool {
	return ch != nil && (ch.Type == model.ChannelTypeDirect || ch.Type == model.ChannelTypeGroup)
}

// channelRecipients returns every member of a DM or group DM except the sender.
// It exists because recipients must match channel membership exactly, never a client-chosen list.
func (p *Plugin) channelRecipients(channelID, senderID string) ([]string, error) {
	ch, appErr := p.API.GetChannel(channelID)
	if appErr != nil {
		return nil, errors.New("channel not found")
	}
	if !isSecretChannel(ch) {
		return nil, errors.New("secret messages can only be sent in direct and group messages")
	}
	members, appErr := p.API.GetChannelMembers(channelID, 0, maxGroupMembers+1)
	if appErr != nil {
		return nil, errors.New("could not read channel members")
	}
	isMember := false
	var out []string
	for _, m := range members {
		if m.UserId == senderID {
			isMember = true
			continue
		}
		out = append(out, m.UserId)
	}
	if !isMember {
		return nil, errors.New("you are not a member of this channel")
	}
	if ch.Type == model.ChannelTypeDirect && len(out) == 0 {
		return nil, errors.New("secret messages to yourself are not supported")
	}
	return out, nil
}

// getJSON reads a KV value into out and reports whether the key existed.
func (p *Plugin) getJSON(key string, out any) (bool, error) {
	data, appErr := p.API.KVGet(key)
	if appErr != nil {
		return false, appErr
	}
	if data == nil {
		return false, nil
	}
	return true, json.Unmarshal(data, out)
}

// setJSON writes a value to the KV store as JSON.
func (p *Plugin) setJSON(key string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if appErr := p.API.KVSet(key, data); appErr != nil {
		return appErr
	}
	return nil
}

// createSecret stores each recipient's envelope and posts the placeholder in the channel.
func (p *Plugin) createSecret(senderID, channelID, rootID string, envelopes map[string]envelope) (*model.Post, error) {
	recipients, err := p.channelRecipients(channelID, senderID)
	if err != nil {
		return nil, err
	}
	if len(envelopes) != len(recipients) {
		return nil, errors.New("there must be exactly one envelope per recipient")
	}
	for _, uid := range recipients {
		env, ok := envelopes[uid]
		if !ok {
			return nil, fmt.Errorf("missing envelope for recipient %s", uid)
		}
		if err := validateEnvelope(env); err != nil {
			return nil, fmt.Errorf("envelope for %s: %w", uid, err)
		}
		var rec publicKeyRecord
		found, err := p.getJSON(keyPrefixPubKey+uid, &rec)
		if err != nil || !found {
			return nil, fmt.Errorf("recipient %s has no registered key", uid)
		}
		if rec.KeyID != env.KeyID {
			return nil, fmt.Errorf("recipient %s changed their key; reopen the composer and send again", uid)
		}
	}

	expiresAt := time.Now().Add(p.getConfiguration().expiry()).UnixMilli()
	nonce := model.NewId()
	post := &model.Post{
		UserId:    senderID,
		ChannelId: channelID,
		RootId:    rootID,
		Type:      PostType,
		Message:   Placeholder,
	}
	post.AddProp(propVersion, 1)
	post.AddProp(propRecipients, recipients)
	post.AddProp(propExpiresAt, expiresAt)
	post.AddProp(propNonce, nonce)

	p.pendingCreates.Store(nonce, true)
	created, appErr := p.API.CreatePost(post)
	p.pendingCreates.Delete(nonce)
	if appErr != nil {
		return nil, errors.Wrap(appErr, "failed to create post")
	}

	p.secretsLock.Lock()
	defer p.secretsLock.Unlock()
	for _, uid := range recipients {
		if err := p.setJSON(envelopeKey(created.Id, uid), envelopes[uid]); err != nil {
			return nil, errors.Wrap(err, "failed to store envelope")
		}
	}
	idx := secretIndex{PostID: created.Id, ChannelID: channelID, SenderID: senderID, Remaining: recipients, ExpiresAt: expiresAt}
	if err := p.setJSON(keyPrefixIndex+created.Id, idx); err != nil {
		return nil, errors.Wrap(err, "failed to store secret index")
	}
	return created, nil
}

// ackSecret deletes one recipient's envelope after they decrypted it, burning the post when none remain.
func (p *Plugin) ackSecret(postID, userID string) error {
	p.secretsLock.Lock()
	defer p.secretsLock.Unlock()

	if appErr := p.API.KVDelete(envelopeKey(postID, userID)); appErr != nil {
		return appErr
	}
	var idx secretIndex
	found, err := p.getJSON(keyPrefixIndex+postID, &idx)
	if err != nil || !found {
		return err
	}
	remaining := idx.Remaining[:0]
	for _, uid := range idx.Remaining {
		if uid != userID {
			remaining = append(remaining, uid)
		}
	}
	idx.Remaining = remaining
	if len(idx.Remaining) > 0 {
		return p.setJSON(keyPrefixIndex+postID, idx)
	}
	return p.burnLocked(idx)
}

// burnLocked removes every envelope and the index for a secret and marks its post burned.
// The caller must hold secretsLock.
func (p *Plugin) burnLocked(idx secretIndex) error {
	for _, uid := range idx.Remaining {
		if appErr := p.API.KVDelete(envelopeKey(idx.PostID, uid)); appErr != nil {
			return appErr
		}
	}
	if appErr := p.API.KVDelete(keyPrefixIndex + idx.PostID); appErr != nil {
		return appErr
	}
	post, appErr := p.API.GetPost(idx.PostID)
	if appErr != nil {
		return nil // post already gone; nothing left to mark
	}
	post.AddProp(propBurned, true)
	post.AddProp(propBurnedAt, time.Now().UnixMilli())
	p.pendingUpdates.Store(post.Id, true)
	_, appErr = p.API.UpdatePost(post)
	p.pendingUpdates.Delete(post.Id)
	if appErr != nil {
		return errors.Wrap(appErr, "failed to mark post burned")
	}
	return nil
}

// sweepExpired burns every secret whose expiry has passed. It runs once a minute on one node.
func (p *Plugin) sweepExpired() {
	now := time.Now().UnixMilli()
	for page := 0; ; page++ {
		keys, appErr := p.API.KVList(page, 200)
		if appErr != nil {
			p.API.LogError("expiry sweep: KVList failed", "err", appErr.Error())
			return
		}
		for _, k := range keys {
			if !strings.HasPrefix(k, keyPrefixIndex) {
				continue
			}
			p.sweepOne(k, now)
		}
		if len(keys) < 200 {
			return
		}
	}
}

// sweepOne burns a single secret if it has expired.
func (p *Plugin) sweepOne(key string, now int64) {
	p.secretsLock.Lock()
	defer p.secretsLock.Unlock()
	var idx secretIndex
	found, err := p.getJSON(key, &idx)
	if err != nil || !found || idx.ExpiresAt > now {
		return
	}
	if err := p.burnLocked(idx); err != nil {
		p.API.LogError("expiry sweep: burn failed", "post_id", idx.PostID, "err", err.Error())
		return
	}
	p.API.LogInfo("expiry sweep: burned expired secret", "post_id", idx.PostID)
}
