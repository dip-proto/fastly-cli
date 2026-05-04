package global_test

import (
	"testing"

	"github.com/fastly/cli/pkg/config"
	"github.com/fastly/cli/pkg/credentials"
	"github.com/fastly/cli/pkg/global"
	"github.com/fastly/cli/pkg/lookup"
	"github.com/fastly/cli/pkg/manifest"
	"github.com/fastly/cli/pkg/threadsafe"
)

func makeData(creds map[string]*credentials.Token, defaultName string) *global.Data {
	s := credentials.NewMemoryStore()
	for n, t := range creds {
		_ = s.Set(n, t)
	}
	if defaultName != "" {
		_ = s.SetDefault(defaultName)
	}
	return &global.Data{Credentials: s}
}

func TestToken(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*global.Data)
		creds      map[string]*credentials.Token
		defaultC   string
		wantToken  string
		wantSource lookup.Source
	}{
		{
			name: "token flag matches stored auth token name",
			mutate: func(d *global.Data) {
				d.Flags.Token = "myname"
			},
			creds: map[string]*credentials.Token{
				"myname": {Type: credentials.TypeStatic, Token: "stored-token-value"},
			},
			defaultC:   "myname",
			wantToken:  "stored-token-value",
			wantSource: lookup.SourceAuth,
		},
		{
			name: "token flag raw value when no stored name matches",
			mutate: func(d *global.Data) {
				d.Flags.Token = "raw-api-token"
			},
			creds: map[string]*credentials.Token{
				"user": {Type: credentials.TypeStatic, Token: "other-token"},
			},
			defaultC:   "user",
			wantToken:  "raw-api-token",
			wantSource: lookup.SourceFlag,
		},
		{
			name: "manifest profile selects stored auth token",
			mutate: func(d *global.Data) {
				d.Manifest = &manifest.Data{File: manifest.File{Profile: "proj"}}
			},
			creds: map[string]*credentials.Token{
				"default-user": {Type: credentials.TypeStatic, Token: "default-token"},
				"proj":         {Type: credentials.TypeStatic, Token: "project-token"},
			},
			defaultC:   "default-user",
			wantToken:  "project-token",
			wantSource: lookup.SourceAuth,
		},
		{
			name: "manifest profile falls through when no matching auth token",
			mutate: func(d *global.Data) {
				d.Manifest = &manifest.Data{File: manifest.File{Profile: "missing"}}
			},
			creds: map[string]*credentials.Token{
				"user": {Type: credentials.TypeStatic, Token: "default-token"},
			},
			defaultC:   "user",
			wantToken:  "default-token",
			wantSource: lookup.SourceAuth,
		},
		{
			name: "env var takes precedence over manifest profile",
			mutate: func(d *global.Data) {
				d.Env = config.Environment{APIToken: "env-token"}
				d.Manifest = &manifest.Data{File: manifest.File{Profile: "proj"}}
			},
			creds: map[string]*credentials.Token{
				"proj": {Type: credentials.TypeStatic, Token: "project-token"},
			},
			defaultC:   "user",
			wantToken:  "env-token",
			wantSource: lookup.SourceEnvironment,
		},
		{
			name:       "no token sources returns undefined",
			creds:      nil,
			wantToken:  "",
			wantSource: lookup.SourceUndefined,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := makeData(tt.creds, tt.defaultC)
			if tt.mutate != nil {
				tt.mutate(d)
			}
			gotToken, gotSource := d.Token()
			if gotToken != tt.wantToken {
				t.Errorf("Token() token = %q, want %q", gotToken, tt.wantToken)
			}
			if gotSource != tt.wantSource {
				t.Errorf("Token() source = %v, want %v", gotSource, tt.wantSource)
			}
		})
	}
}

func TestAuthTokenName(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*global.Data)
		creds    map[string]*credentials.Token
		defaultC string
		wantName string
	}{
		{
			name: "token flag matches stored name",
			mutate: func(d *global.Data) {
				d.Flags.Token = "myname"
			},
			creds:    map[string]*credentials.Token{"myname": {Token: "t"}},
			wantName: "myname",
		},
		{
			name: "token flag raw value returns empty",
			mutate: func(d *global.Data) {
				d.Flags.Token = "raw-value"
			},
			creds:    map[string]*credentials.Token{"user": {Token: "t"}},
			wantName: "",
		},
		{
			name: "manifest profile returns profile name",
			mutate: func(d *global.Data) {
				d.Manifest = &manifest.Data{File: manifest.File{Profile: "proj"}}
			},
			creds: map[string]*credentials.Token{
				"default-user": {Token: "t"},
				"proj":         {Token: "t2"},
			},
			defaultC: "default-user",
			wantName: "proj",
		},
		{
			name: "manifest profile missing falls through to default",
			mutate: func(d *global.Data) {
				d.Manifest = &manifest.Data{File: manifest.File{Profile: "missing"}}
			},
			creds:    map[string]*credentials.Token{"user": {Token: "t"}},
			defaultC: "user",
			wantName: "user",
		},
		{
			name:     "default auth token name",
			creds:    map[string]*credentials.Token{"user": {Token: "t"}},
			defaultC: "user",
			wantName: "user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := makeData(tt.creds, tt.defaultC)
			if tt.mutate != nil {
				tt.mutate(d)
			}
			got := d.AuthTokenName()
			if got != tt.wantName {
				t.Errorf("AuthTokenName() = %q, want %q", got, tt.wantName)
			}
		})
	}
}

func TestTokenManifestProfileMissingNoSideEffect(t *testing.T) {
	var buf threadsafe.Buffer
	d := makeData(map[string]*credentials.Token{
		"user": {Type: credentials.TypeStatic, Token: "default-token"},
	}, "user")
	d.Manifest = &manifest.Data{File: manifest.File{Profile: "missing"}}
	d.Output = &buf

	token, source := d.Token()
	if token != "default-token" {
		t.Errorf("Token() = %q, want %q", token, "default-token")
	}
	if source != lookup.SourceAuth {
		t.Errorf("Token() source = %v, want %v", source, lookup.SourceAuth)
	}
	if buf.String() != "" {
		t.Errorf("Token() should not write to output, got: %q", buf.String())
	}
}
