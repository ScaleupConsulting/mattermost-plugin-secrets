package main

import (
	"sync"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
	"github.com/mattermost/mattermost/server/public/pluginapi"
	"github.com/mattermost/mattermost/server/public/pluginapi/cluster"
	"github.com/pkg/errors"
)

// Plugin implements the interface expected by the Mattermost server to communicate between the server and plugin processes.
type Plugin struct {
	plugin.MattermostPlugin

	client *pluginapi.Client

	sweepJob *cluster.Job

	// secretsLock serialises read-modify-write of secret index records (single node only).
	secretsLock sync.Mutex

	// pendingCreates holds one-time nonces of secret posts this plugin is creating itself.
	pendingCreates sync.Map

	// pendingUpdates holds IDs of secret posts this plugin is about to update itself.
	pendingUpdates sync.Map

	// uploadLocks holds a *sync.Mutex per upload ID, serialising chunk writes, attach and sweep on this node.
	uploadLocks sync.Map

	// uploadsLock serialises the quota check and reservation when uploads start (single node only).
	uploadsLock sync.Mutex

	// configurationLock synchronizes access to the configuration.
	configurationLock sync.RWMutex

	// configuration is the active plugin configuration. Consult getConfiguration and
	// setConfiguration for usage.
	configuration *configuration
}

// OnActivate registers the slash command and schedules the expiry sweeper.
func (p *Plugin) OnActivate() error {
	p.client = pluginapi.NewClient(p.API, p.Driver)

	if err := p.API.RegisterCommand(&model.Command{
		Trigger:          commandTrigger,
		DisplayName:      "Secret message",
		Description:      "Send a one-time secret, encrypted in your browser for each recipient.",
		AutoComplete:     true,
		AutoCompleteDesc: "Open the secret message composer (direct and group messages only)",
	}); err != nil {
		return errors.Wrap(err, "failed to register /secret command")
	}

	job, err := cluster.Schedule(p.API, "SecretExpirySweep", cluster.MakeWaitForInterval(time.Minute), p.sweepExpired)
	if err != nil {
		return errors.Wrap(err, "failed to schedule expiry sweep")
	}
	p.sweepJob = job
	return nil
}

// OnDeactivate stops the expiry sweeper.
func (p *Plugin) OnDeactivate() error {
	if p.sweepJob != nil {
		if err := p.sweepJob.Close(); err != nil {
			p.API.LogError("Failed to close expiry sweep job", "err", err.Error())
		}
	}
	return nil
}
