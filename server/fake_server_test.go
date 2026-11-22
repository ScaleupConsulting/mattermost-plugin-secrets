package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
	"github.com/mattermost/mattermost/server/public/plugin/plugintest"
	"github.com/mattermost/mattermost/server/public/pluginapi"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// fakeServer backs plugintest.API with an in-memory KV store, users, channels and posts.
type fakeServer struct {
	mu       sync.Mutex
	kv       map[string][]byte
	users    map[string]*model.User
	channels map[string]*model.Channel
	members  map[string][]string
	posts    map[string]*model.Post
	audits   []*model.AuditRecord
}

// testWorld names the users and channel every test starts with.
type testWorld struct {
	sender, recipient, outsider, bot string
	dm, botDM, openChannel           string
}

// newTestPlugin builds a plugin on a fake server with a DM between sender and recipient,
// a DM between the bot and recipient, and a registered key for the recipient.
func newTestPlugin(t *testing.T, conf *configuration) (*Plugin, *fakeServer, testWorld) {
	t.Helper()
	f := &fakeServer{
		kv:       map[string][]byte{},
		users:    map[string]*model.User{},
		channels: map[string]*model.Channel{},
		members:  map[string][]string{},
		posts:    map[string]*model.Post{},
	}
	w := testWorld{
		sender: model.NewId(), recipient: model.NewId(), outsider: model.NewId(), bot: model.NewId(),
		dm: model.NewId(), botDM: model.NewId(), openChannel: model.NewId(),
	}
	for _, id := range []string{w.sender, w.recipient, w.outsider} {
		f.users[id] = &model.User{Id: id, Username: "u" + id[:6]}
	}
	f.users[w.bot] = &model.User{Id: w.bot, Username: "bot", IsBot: true}
	f.channels[w.dm] = &model.Channel{Id: w.dm, Type: model.ChannelTypeDirect}
	f.channels[w.botDM] = &model.Channel{Id: w.botDM, Type: model.ChannelTypeDirect}
	f.channels[w.openChannel] = &model.Channel{Id: w.openChannel, Type: model.ChannelTypeOpen}
	f.members[w.dm] = []string{w.sender, w.recipient}
	f.members[w.botDM] = []string{w.bot, w.recipient}
	f.members[w.openChannel] = []string{w.sender, w.recipient, w.outsider}

	api := &plugintest.API{}
	p := &Plugin{}
	p.SetAPI(api)
	p.client = pluginapi.NewClient(api, &plugintest.Driver{})
	if conf == nil {
		conf = &configuration{}
	}
	p.setConfiguration(conf)
	f.install(api, p)

	pub := testPublicKey(t)
	kid, err := parsePublicKey(pub)
	require.NoError(t, err)
	require.NoError(t, p.setJSON(keyPrefixPubKey+w.recipient, publicKeyRecord{PublicKey: pub, KeyID: kid}))
	return p, f, w
}

// testPublicKey returns a fresh base64 SPKI P-256 public key.
func testPublicKey(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(der)
}

// notFound is the AppError the fake returns for missing objects.
func notFound() *model.AppError {
	return model.NewAppError("fake", "not_found", nil, "", http.StatusNotFound)
}

// install registers the fake's behaviour on every plugin API method the plugin calls.
func (f *fakeServer) install(api *plugintest.API, p *Plugin) {
	api.On("KVGet", mock.Anything).Return(func(key string) ([]byte, *model.AppError) {
		f.mu.Lock()
		defer f.mu.Unlock()
		v, ok := f.kv[key]
		if !ok {
			return nil, nil
		}
		return append([]byte(nil), v...), nil
	}).Maybe()
	api.On("KVSet", mock.Anything, mock.Anything).Return(func(key string, value []byte) *model.AppError {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.kv[key] = append([]byte(nil), value...)
		return nil
	}).Maybe()
	api.On("KVDelete", mock.Anything).Return(func(key string) *model.AppError {
		f.mu.Lock()
		defer f.mu.Unlock()
		delete(f.kv, key)
		return nil
	}).Maybe()
	api.On("KVSetWithOptions", mock.Anything, mock.Anything, mock.Anything).Return(func(key string, value []byte, o model.PluginKVSetOptions) (bool, *model.AppError) {
		f.mu.Lock()
		defer f.mu.Unlock()
		cur, exists := f.kv[key]
		if o.Atomic {
			if o.OldValue == nil && exists || o.OldValue != nil && (!exists || !bytes.Equal(cur, o.OldValue)) {
				return false, nil
			}
		}
		if value == nil {
			delete(f.kv, key)
		} else {
			f.kv[key] = append([]byte(nil), value...)
		}
		return true, nil
	}).Maybe()
	api.On("KVListWithOptions", mock.Anything, mock.Anything, mock.Anything).Return(func(page, perPage int, o model.PluginKVListOptions) ([]string, *model.AppError) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var keys []string
		for k := range f.kv {
			if strings.HasPrefix(k, o.Prefix) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		start := min(page*perPage, len(keys))
		return keys[start:min(start+perPage, len(keys))], nil
	}).Maybe()
	api.On("GetUser", mock.Anything).Return(func(id string) (*model.User, *model.AppError) {
		if u, ok := f.users[id]; ok {
			return u, nil
		}
		return nil, notFound()
	}).Maybe()
	api.On("GetChannel", mock.Anything).Return(func(id string) (*model.Channel, *model.AppError) {
		if c, ok := f.channels[id]; ok {
			return c, nil
		}
		return nil, notFound()
	}).Maybe()
	api.On("GetChannelMembers", mock.Anything, mock.Anything, mock.Anything).Return(func(id string, _, _ int) (model.ChannelMembers, *model.AppError) {
		var out model.ChannelMembers
		for _, uid := range f.members[id] {
			out = append(out, model.ChannelMember{ChannelId: id, UserId: uid})
		}
		return out, nil
	}).Maybe()
	api.On("GetChannelMember", mock.Anything, mock.Anything).Return(func(channelID, userID string) (*model.ChannelMember, *model.AppError) {
		if slices.Contains(f.members[channelID], userID) {
			return &model.ChannelMember{ChannelId: channelID, UserId: userID}, nil
		}
		return nil, notFound()
	}).Maybe()
	api.On("GetPost", mock.Anything).Return(func(id string) (*model.Post, *model.AppError) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if post, ok := f.posts[id]; ok {
			return post.Clone(), nil
		}
		return nil, notFound()
	}).Maybe()
	api.On("CreatePost", mock.Anything).Return(func(post *model.Post) (*model.Post, *model.AppError) {
		if _, reason := p.MessageWillBePosted(&plugin.Context{}, post); reason != "" {
			return nil, model.NewAppError("fake", "rejected", nil, reason, http.StatusBadRequest)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		created := post.Clone()
		created.Id = model.NewId()
		f.posts[created.Id] = created
		return created.Clone(), nil
	}).Maybe()
	api.On("UpdatePost", mock.Anything).Return(func(post *model.Post) (*model.Post, *model.AppError) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.posts[post.Id] = post.Clone()
		return post, nil
	}).Maybe()
	api.On("DeletePost", mock.Anything).Return(func(id string) *model.AppError {
		f.mu.Lock()
		defer f.mu.Unlock()
		delete(f.posts, id)
		return nil
	}).Maybe()
	api.On("LogAuditRec", mock.Anything).Run(func(args mock.Arguments) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.audits = append(f.audits, args.Get(0).(*model.AuditRecord))
	}).Return().Maybe()
	for _, level := range []string{"LogError", "LogWarn", "LogInfo", "LogDebug"} {
		for n := 1; n <= 9; n += 2 {
			args := make([]any, n)
			for i := range args {
				args[i] = mock.Anything
			}
			api.On(level, args...).Return().Maybe()
		}
	}
}

// keysWithPrefix lists the fake KV keys with a prefix.
func (f *fakeServer) keysWithPrefix(prefix string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for k := range f.kv {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// do sends a request through the plugin's router as userID ("" for no session).
func do(p *Plugin, userID, method, path string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/api/v1"+path, bytes.NewReader(body))
	if userID != "" {
		req.Header.Set("Mattermost-User-ID", userID)
	}
	rec := httptest.NewRecorder()
	p.ServeHTTP(&plugin.Context{}, rec, req)
	return rec
}

// mustJSON marshals v or fails the test.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}
