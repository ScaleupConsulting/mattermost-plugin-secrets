package main

import (
	"reflect"
	"time"

	"github.com/pkg/errors"
)

// configuration captures the plugin's external configuration as exposed in the Mattermost server
// configuration, as well as values computed from the configuration. Any public fields will be
// deserialized from the Mattermost server configuration in OnConfigurationChange.
//
// As plugins are inherently concurrent (hooks being called asynchronously), and the plugin
// configuration can change at any time, access to the configuration must be synchronized. The
// strategy used in this plugin is to guard a pointer to the configuration, and clone the entire
// struct whenever it changes. You may replace this with whatever strategy you choose.
//
// If you add non-reference types to your configuration struct, be sure to rewrite Clone as a deep
// copy appropriate for your types.
type configuration struct {
	// ExpiryMinutes is how long unread ciphertext lives before the sweeper deletes it.
	ExpiryMinutes int

	// FileSecretSenders is who may attach files: everyone, bots or nobody.
	FileSecretSenders string

	// MaxStorageMB bounds all file data in the KV store, uploads in progress included.
	MaxStorageMB int

	// UploadSessionMinutes is how long an unfinished upload lives.
	UploadSessionMinutes int
}

const (
	sendersEveryone = "everyone"
	sendersBots     = "bots"
	sendersNobody   = "nobody"

	defaultMaxStorageMB         = 2048
	defaultUploadSessionMinutes = 60

	bytesPerMB = 1 << 20
)

// defaultExpiryMinutes is 7 days, used when the admin leaves the setting empty or invalid.
const defaultExpiryMinutes = 7 * 24 * 60

// expiry returns the configured ciphertext lifetime, falling back to 7 days when unset.
func (c *configuration) expiry() time.Duration {
	if c.ExpiryMinutes <= 0 {
		return defaultExpiryMinutes * time.Minute
	}
	return time.Duration(c.ExpiryMinutes) * time.Minute
}

// fileSenders returns who may send file secrets, treating an unset or unknown value as everyone.
func (c *configuration) fileSenders() string {
	switch c.FileSecretSenders {
	case sendersBots, sendersNobody:
		return c.FileSecretSenders
	default:
		return sendersEveryone
	}
}

// maxStorageBytes returns the cap on file data across all users.
func (c *configuration) maxStorageBytes() int64 {
	if c.MaxStorageMB <= 0 {
		return defaultMaxStorageMB * bytesPerMB
	}
	return int64(c.MaxStorageMB) * bytesPerMB
}

// uploadSession returns how long an unfinished upload lives.
func (c *configuration) uploadSession() time.Duration {
	if c.UploadSessionMinutes <= 0 {
		return defaultUploadSessionMinutes * time.Minute
	}
	return time.Duration(c.UploadSessionMinutes) * time.Minute
}

// Clone shallow copies the configuration. Your implementation may require a deep copy if
// your configuration has reference types.
func (c *configuration) Clone() *configuration {
	clone := *c
	return &clone
}

// getConfiguration retrieves the active configuration under lock, making it safe to use
// concurrently. The active configuration may change underneath the client of this method, but
// the struct returned by this API call is considered immutable.
func (p *Plugin) getConfiguration() *configuration {
	p.configurationLock.RLock()
	defer p.configurationLock.RUnlock()

	if p.configuration == nil {
		return &configuration{}
	}

	return p.configuration
}

// setConfiguration replaces the active configuration under lock.
//
// Do not call setConfiguration while holding the configurationLock, as sync.Mutex is not
// reentrant. In particular, avoid using the plugin API entirely, as this may in turn trigger a
// hook back into the plugin. If that hook attempts to acquire this lock, a deadlock may occur.
//
// This method panics if setConfiguration is called with the existing configuration. This almost
// certainly means that the configuration was modified without being cloned and may result in
// an unsafe access.
func (p *Plugin) setConfiguration(configuration *configuration) {
	p.configurationLock.Lock()
	defer p.configurationLock.Unlock()

	if configuration != nil && p.configuration == configuration {
		// Ignore assignment if the configuration struct is empty. Go will optimize the
		// allocation for same to point at the same memory address, breaking the check
		// above.
		if reflect.ValueOf(*configuration).NumField() == 0 {
			return
		}

		panic("setConfiguration called with the existing configuration")
	}

	p.configuration = configuration
}

// OnConfigurationChange is invoked when configuration changes may have been made.
func (p *Plugin) OnConfigurationChange() error {
	configuration := new(configuration)

	// Load the public configuration fields from the Mattermost server configuration.
	if err := p.API.LoadPluginConfiguration(configuration); err != nil {
		return errors.Wrap(err, "failed to load plugin configuration")
	}

	p.setConfiguration(configuration)

	return nil
}
