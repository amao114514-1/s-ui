package service

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alireza0/s-ui/database"
	"github.com/alireza0/s-ui/database/model"
	"gorm.io/gorm"
)

func initServiceTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "s-ui.db")
	if err := database.InitDB(dbPath); err != nil {
		if strings.Contains(err.Error(), "go-sqlite3 requires cgo") {
			t.Skipf("sqlite cgo is unavailable in this test environment: %v", err)
		}
		t.Fatal(err)
	}
	return database.GetDB()
}

func setTestSetting(t *testing.T, db *gorm.DB, key string, value string) {
	t.Helper()
	setting := model.Setting{Key: key}
	if err := db.Where("key = ?", key).Assign(model.Setting{Value: value}).FirstOrCreate(&setting).Error; err != nil {
		t.Fatal(err)
	}
}

func TestConfiguredHostParsesWebURIForms(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "bare IPv4", in: "157.245.135.117", want: "157.245.135.117"},
		{name: "bare domain", in: "panel.example.com", want: "panel.example.com"},
		{name: "URL with port and path", in: "https://panel.example.com:2095/app/", want: "panel.example.com"},
		{name: "host port with path", in: "panel.example.com:2095/app/", want: "panel.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := configuredHost(tt.in); got != tt.want {
				t.Fatalf("configuredHost(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestGetCanonicalHostPrefersBareWebURIOverLocalRequestHost(t *testing.T) {
	db := initServiceTestDB(t)
	setTestSetting(t, db, "webURI", "157.245.135.117")

	host, err := (&SettingService{}).GetCanonicalHost("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if host != "157.245.135.117" {
		t.Fatalf("expected configured webURI host, got %q", host)
	}
}

func TestGetCanonicalHostAcceptsURLWebURI(t *testing.T) {
	db := initServiceTestDB(t)
	setTestSetting(t, db, "webURI", "https://panel.example.com:2095/app/")

	host, err := (&SettingService{}).GetCanonicalHost("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if host != "panel.example.com" {
		t.Fatalf("expected hostname from webURI URL, got %q", host)
	}
}

func TestClientSaveUsesWebURIForGeneratedVLESSRealityLinks(t *testing.T) {
	db := initServiceTestDB(t)
	setTestSetting(t, db, "webURI", "157.245.135.117")

	tlsConfig := model.Tls{
		Name: "reality-template",
		Server: json.RawMessage(`{
			"enabled": true,
			"server_name": "www.microsoft.com",
			"reality": {
				"enabled": true,
				"short_id": ["abcdef12"]
			}
		}`),
		Client: json.RawMessage(`{
			"enabled": true,
			"server_name": "www.microsoft.com",
			"reality": {
				"enabled": true,
				"public_key": "public-key-test",
				"short_id": ""
			},
			"utls": {
				"enabled": true,
				"fingerprint": "chrome"
			}
		}`),
	}
	if err := db.Create(&tlsConfig).Error; err != nil {
		t.Fatal(err)
	}

	inbound := model.Inbound{
		Type:    "vless",
		Tag:     "vless-reality",
		TlsId:   tlsConfig.Id,
		Addrs:   json.RawMessage(`[]`),
		OutJson: json.RawMessage(`{}`),
		Options: json.RawMessage(`{
			"listen_port": 443,
			"transport": {
				"type": "tcp"
			}
		}`),
	}
	if err := db.Create(&inbound).Error; err != nil {
		t.Fatal(err)
	}

	hostname, err := (&SettingService{}).GetCanonicalHost("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	clientData := map[string]interface{}{
		"enable":   true,
		"name":     "alice",
		"remark":   "alice",
		"inbounds": []uint{inbound.Id},
		"links":    []map[string]string{},
		"config": map[string]map[string]string{
			"vless": {
				"uuid": "11111111-1111-4111-8111-111111111111",
				"flow": "xtls-rprx-vision",
			},
		},
	}
	rawClient, err := json.Marshal(clientData)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&ClientService{}).Save(db, "new", rawClient, hostname); err != nil {
		t.Fatal(err)
	}

	var saved model.Client
	if err := db.Where("name = ?", "alice").First(&saved).Error; err != nil {
		t.Fatal(err)
	}
	var linkRows []map[string]string
	if err := json.Unmarshal(saved.Links, &linkRows); err != nil {
		t.Fatalf("links should remain json.RawMessage compatible: %v", err)
	}
	if len(linkRows) != 1 {
		t.Fatalf("expected one generated link, got %d", len(linkRows))
	}
	uri := linkRows[0]["uri"]
	required := []string{
		"vless://",
		"@157.245.135.117:443",
		"security=reality",
		"pbk=public-key-test",
		"sid=abcdef12",
		"sni=www.microsoft.com",
		"fp=chrome",
		"flow=xtls-rprx-vision",
	}
	for _, part := range required {
		if !strings.Contains(uri, part) {
			t.Fatalf("generated link missing %q: %s", part, uri)
		}
	}
	if strings.Contains(uri, "127.0.0.1") {
		t.Fatalf("generated link must not use local panel host: %s", uri)
	}

	var storageType string
	if err := db.Raw("select typeof(links) from clients where id = ?", saved.Id).Scan(&storageType).Error; err != nil {
		t.Fatal(err)
	}
	if storageType != "blob" {
		t.Fatalf("clients.links must remain BLOB/json.RawMessage compatible, got %q", storageType)
	}
}
