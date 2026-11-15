package main

import (
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
)

// MessageWillBePosted refuses any secret post that is malformed, carries text other than the
// placeholder, sits outside a DM or group DM, or was not created by this plugin's own endpoint.
func (p *Plugin) MessageWillBePosted(_ *plugin.Context, post *model.Post) (*model.Post, string) {
	if post.Type != PostType {
		return post, ""
	}
	if reason := p.validateSecretPost(post); reason != "" {
		p.API.LogWarn("rejected secret post", "user_id", post.UserId, "channel_id", post.ChannelId, "reason", reason)
		return nil, reason
	}
	return post, ""
}

// validateSecretPost returns why a custom_secret post is unacceptable, or "" if it is fine.
func (p *Plugin) validateSecretPost(post *model.Post) string {
	ch, appErr := p.API.GetChannel(post.ChannelId)
	if appErr != nil || !isSecretChannel(ch) {
		return "Secret messages are only allowed in direct and group messages."
	}
	if post.Message != Placeholder {
		return "A secret post's message must be the fixed placeholder; secret text is never accepted in plaintext."
	}
	if len(post.FileIds) > 0 {
		return "Secret posts cannot carry file attachments."
	}
	for k := range post.GetProps() {
		if !allowedProps[k] {
			return "Secret post has an unexpected property: " + k
		}
	}
	if _, ok := post.GetProp(propRecipients).([]string); !ok {
		if _, ok := post.GetProp(propRecipients).([]any); !ok {
			return "Secret post is missing its recipient list."
		}
	}
	nonce, _ := post.GetProp(propNonce).(string)
	if _, ok := p.pendingCreates.Load(nonce); nonce == "" || !ok {
		return "Secret posts can only be created through the Secret Messages composer."
	}
	return ""
}

// MessageWillBeUpdated refuses every edit to a secret post, and turning any post into one,
// except the burn marker this plugin writes itself.
func (p *Plugin) MessageWillBeUpdated(_ *plugin.Context, newPost, oldPost *model.Post) (*model.Post, string) {
	if oldPost.Type != PostType && newPost.Type != PostType {
		return newPost, ""
	}
	if _, ok := p.pendingUpdates.Load(oldPost.Id); ok && newPost.Type == PostType && newPost.Message == Placeholder {
		return newPost, ""
	}
	p.API.LogWarn("rejected edit to secret post", "post_id", oldPost.Id, "user_id", newPost.UserId)
	return nil, "Secret messages cannot be edited. Delete it and send a new one."
}

// MessageHasBeenDeleted removes any remaining ciphertext when a secret post is deleted.
func (p *Plugin) MessageHasBeenDeleted(_ *plugin.Context, post *model.Post) {
	if post.Type != PostType {
		return
	}
	p.secretsLock.Lock()
	defer p.secretsLock.Unlock()
	var idx secretIndex
	found, err := p.getJSON(keyPrefixIndex+post.Id, &idx)
	if err != nil || !found {
		return
	}
	for _, uid := range idx.Remaining {
		_ = p.API.KVDelete(envelopeKey(post.Id, uid))
	}
	_ = p.API.KVDelete(keyPrefixIndex + post.Id)
}
