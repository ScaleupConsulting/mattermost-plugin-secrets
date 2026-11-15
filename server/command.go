package main

import (
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
)

const commandTrigger = "secret"

// ExecuteCommand only runs when the webapp did not intercept /secret, e.g. on mobile or in a
// channel the webapp already refused, so it never accepts secret text.
func (p *Plugin) ExecuteCommand(_ *plugin.Context, args *model.CommandArgs) (*model.CommandResponse, *model.AppError) {
	text := "Secret messages can only be composed in Mattermost on desktop or web. Nothing was sent."
	if ch, appErr := p.API.GetChannel(args.ChannelId); appErr != nil || !isSecretChannel(ch) {
		text = "Secret messages can only be sent in direct and group messages. Nothing was sent."
	}
	return &model.CommandResponse{ResponseType: model.CommandResponseTypeEphemeral, Text: text}, nil
}
