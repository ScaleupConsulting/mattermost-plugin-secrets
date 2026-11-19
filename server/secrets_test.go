package main

import (
	"testing"

	"github.com/mattermost/mattermost/server/public/model"
)

// TestAllowedPropsAcceptsBotSenders guards the bot path: the server adds from_bot to every
// bot post, and rejecting it stops bots such as the website relay from sending secrets.
func TestAllowedPropsAcceptsBotSenders(t *testing.T) {
	if !allowedProps[model.PostPropsFromBot] {
		t.Fatalf("allowedProps must include %q", model.PostPropsFromBot)
	}
}
