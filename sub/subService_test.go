package sub

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alireza0/s-ui/database"
	"github.com/alireza0/s-ui/database/model"
	"github.com/alireza0/s-ui/logger"
	"github.com/alireza0/s-ui/service"

	"github.com/op/go-logging"
)

func TestSubscriptionLookupUsesTokenNotClientName(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "s-ui.db")
	if err := database.InitDB(dbPath); err != nil {
		if strings.Contains(err.Error(), "go-sqlite3 requires cgo") {
			t.Skipf("sqlite cgo is unavailable in this test environment: %v", err)
		}
		t.Fatal(err)
	}

	client := model.Client{
		Enable:            true,
		Name:              "alice",
		SubscriptionToken: "token-alice",
		Config:            json.RawMessage(`{}`),
		Inbounds:          json.RawMessage(`[]`),
		Links:             json.RawMessage(`[]`),
	}
	if err := database.GetDB().Create(&client).Error; err != nil {
		t.Fatal(err)
	}

	service := SubService{}
	if _, err := service.getClientBySubId("alice"); err == nil {
		t.Fatal("client name must not authorize subscription access")
	}
	if _, err := service.getClientBySubId("token-alice"); err != nil {
		t.Fatalf("subscription token should authorize subscription access: %v", err)
	}
}

func TestExpiredClientRestoreReenablesSubscriptionAndRuntimeConfig(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "s-ui.db")
	if err := database.InitDB(dbPath); err != nil {
		if strings.Contains(err.Error(), "go-sqlite3 requires cgo") {
			t.Skipf("sqlite cgo is unavailable in this test environment: %v", err)
		}
		t.Fatal(err)
	}
	db := database.GetDB()
	setSubTestSetting(t, "webURI", "157.245.135.117")
	setSubTestSetting(t, "subEncode", "false")

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

	hostname, err := (&service.SettingService{}).GetCanonicalHost("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	expiredAt := time.Now().Unix() - 60
	expiredClient := clientPayload(0, inbound.Id, expiredAt, 0, true)
	if _, err := (&service.ClientService{}).Save(db, "new", mustMarshal(t, expiredClient), hostname); err != nil {
		t.Fatal(err)
	}

	subSvc := SubService{}
	if result, _, err := subSvc.GetSubs("token-recover"); err == nil {
		t.Fatalf("expired client subscription should be rejected, got %q", *result)
	}
	assertRuntimeUserCount(t, inbound.Id, 0)

	var saved model.Client
	if err := db.Where("subscription_token = ?", "token-recover").First(&saved).Error; err != nil {
		t.Fatal(err)
	}

	restoredClient := clientPayload(saved.Id, inbound.Id, 0, 0, true)
	changedInboundIds, err := (&service.ClientService{}).Save(db, "edit", mustMarshal(t, restoredClient), hostname)
	if err != nil {
		t.Fatal(err)
	}
	if len(changedInboundIds) == 0 {
		t.Fatal("restoring an expired client to active should mark its inbound for reload")
	}

	result, headers, err := subSvc.GetSubs("token-recover")
	if err != nil {
		t.Fatalf("restored client subscription should be available: %v", err)
	}
	if result == nil || !strings.Contains(*result, "vless://") {
		t.Fatalf("restored subscription should contain a vless link, got %q", valueOrEmpty(result))
	}
	if !strings.Contains(*result, "@157.245.135.117:443") {
		t.Fatalf("restored link should use configured webURI and port 443, got %q", *result)
	}
	if strings.Contains(*result, "127.0.0.1") {
		t.Fatalf("restored link must not use local panel host: %q", *result)
	}
	if len(headers) == 0 || !strings.Contains(headers[0], "upload=") || !strings.Contains(headers[0], "download=") ||
		!strings.Contains(headers[0], "total=") || !strings.Contains(headers[0], "expire=") {
		t.Fatalf("restored subscription should include Subscription-Userinfo data, got %#v", headers)
	}

	var storageType string
	if err := db.Raw("select typeof(links) from clients where id = ?", saved.Id).Scan(&storageType).Error; err != nil {
		t.Fatal(err)
	}
	if storageType != "blob" {
		t.Fatalf("clients.links must remain BLOB/json.RawMessage compatible, got %q", storageType)
	}
	assertRuntimeUserCount(t, inbound.Id, 1)
}

func TestAutoResetTrafficCycleRestoresQuotaDepletedLongLivedClient(t *testing.T) {
	logger.InitLogger(logging.ERROR)

	dbPath := filepath.Join(t.TempDir(), "s-ui.db")
	if err := database.InitDB(dbPath); err != nil {
		if strings.Contains(err.Error(), "go-sqlite3 requires cgo") {
			t.Skipf("sqlite cgo is unavailable in this test environment: %v", err)
		}
		t.Fatal(err)
	}
	db := database.GetDB()
	setSubTestSetting(t, "webURI", "157.245.135.117")
	setSubTestSetting(t, "subEncode", "false")
	inbound := createRealityInbound(t)

	hostname, err := (&service.SettingService{}).GetCanonicalHost("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	const resetDays = 30
	const resetPeriod = int64(resetDays) * 86400
	volume := int64(100) * 1024 * 1024 * 1024
	beforeSave := time.Now().Unix()
	payload := clientPayload(0, inbound.Id, 0, volume, true)
	payload["name"] = "cycle-user"
	payload["subscriptionToken"] = "token-cycle"
	payload["autoReset"] = true
	payload["resetDays"] = resetDays
	payload["nextReset"] = 0
	if _, err := (&service.ClientService{}).Save(db, "new", mustMarshal(t, payload), hostname); err != nil {
		t.Fatal(err)
	}
	afterSave := time.Now().Unix()

	var saved model.Client
	if err := db.Where("subscription_token = ?", "token-cycle").First(&saved).Error; err != nil {
		t.Fatal(err)
	}
	if saved.Expiry != 0 {
		t.Fatalf("traffic cycle must not change account expiry, got %d", saved.Expiry)
	}
	if !saved.AutoReset || saved.ResetDays != resetDays {
		t.Fatalf("auto reset settings were not saved: autoReset=%v resetDays=%d", saved.AutoReset, saved.ResetDays)
	}
	if saved.NextReset < beforeSave+resetPeriod || saved.NextReset > afterSave+resetPeriod {
		t.Fatalf("nextReset should be initialized from open time + resetDays, got %d want between %d and %d", saved.NextReset, beforeSave+resetPeriod, afterSave+resetPeriod)
	}
	if !service.IsClientActive(&saved, time.Now().Unix()) {
		t.Fatal("long-lived client with unused quota should be active")
	}

	subSvc := SubService{}
	result, headers, err := subSvc.GetSubs("token-cycle")
	if err != nil {
		t.Fatalf("long-lived cycle client subscription should be available: %v", err)
	}
	if result == nil || !strings.Contains(*result, "vless://") || !strings.Contains(*result, "@157.245.135.117:443") || strings.Contains(*result, "127.0.0.1") {
		t.Fatalf("cycle subscription should use configured webURI in a vless link, got %q", valueOrEmpty(result))
	}
	if len(headers) == 0 || !strings.Contains(headers[0], "upload=0") || !strings.Contains(headers[0], "download=0") ||
		!strings.Contains(headers[0], "total=107374182400") || !strings.Contains(headers[0], "expire=0") {
		t.Fatalf("cycle subscription should expose current-cycle userinfo without using nextReset as expire, got %#v", headers)
	}
	assertRuntimeUserCount(t, inbound.Id, 1)

	if err := db.Model(model.Client{}).Where("id = ?", saved.Id).Updates(map[string]interface{}{
		"up":   volume + 1,
		"down": int64(1234),
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Where("id = ?", saved.Id).First(&saved).Error; err != nil {
		t.Fatal(err)
	}
	if service.IsClientActive(&saved, time.Now().Unix()) {
		t.Fatal("client over its current-cycle volume should be inactive")
	}
	if result, _, err := subSvc.GetSubs("token-cycle"); err == nil {
		t.Fatalf("quota-depleted subscription should be rejected, got %q", valueOrEmpty(result))
	}
	assertRuntimeUserCount(t, inbound.Id, 0)

	depletedInboundIds, err := (&service.ClientService{}).DepleteClients()
	if err != nil {
		t.Fatal(err)
	}
	if !containsUint(depletedInboundIds, inbound.Id) {
		t.Fatalf("depleting an over-quota client should mark inbound %d for reload, got %#v", inbound.Id, depletedInboundIds)
	}
	if err := db.Where("id = ?", saved.Id).First(&saved).Error; err != nil {
		t.Fatal(err)
	}
	if saved.Enable {
		t.Fatal("quota-depleted client should be disabled until its next traffic cycle")
	}

	resetAt := time.Now().Unix()
	dueReset := resetAt - 10
	if err := db.Model(model.Client{}).Where("id = ?", saved.Id).Updates(map[string]interface{}{
		"up":         volume + 1,
		"down":       int64(1234),
		"next_reset": dueReset,
		"enable":     false,
	}).Error; err != nil {
		t.Fatal(err)
	}
	tx := db.Begin()
	restoredInboundIds, err := (&service.ClientService{}).ResetClients(tx, resetAt)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit().Error; err != nil {
		t.Fatal(err)
	}
	if !containsUint(restoredInboundIds, inbound.Id) {
		t.Fatalf("traffic cycle reset should mark inbound %d for reload, got %#v", inbound.Id, restoredInboundIds)
	}
	if err := db.Where("id = ?", saved.Id).First(&saved).Error; err != nil {
		t.Fatal(err)
	}
	if !saved.Enable {
		t.Fatal("quota-depleted client should be re-enabled for the next traffic cycle")
	}
	if saved.Up != 0 || saved.Down != 0 {
		t.Fatalf("traffic cycle reset should clear current counters, got up=%d down=%d", saved.Up, saved.Down)
	}
	if saved.TotalUp != volume+1 || saved.TotalDown != 1234 {
		t.Fatalf("traffic cycle reset should accumulate totals, got totalUp=%d totalDown=%d", saved.TotalUp, saved.TotalDown)
	}
	if saved.NextReset != dueReset+resetPeriod {
		t.Fatalf("nextReset should advance from the previous cycle boundary, got %d want %d", saved.NextReset, dueReset+resetPeriod)
	}
	if !service.IsClientActive(&saved, resetAt) {
		t.Fatal("client should be active again after its traffic cycle reset")
	}
	result, headers, err = subSvc.GetSubs("token-cycle")
	if err != nil {
		t.Fatalf("subscription should recover after traffic cycle reset: %v", err)
	}
	if result == nil || !strings.Contains(*result, "vless://") {
		t.Fatalf("recovered subscription should contain vless link, got %q", valueOrEmpty(result))
	}
	if len(headers) == 0 || !strings.Contains(headers[0], "upload=0") || !strings.Contains(headers[0], "download=0") {
		t.Fatalf("recovered subscription should expose reset current-cycle counters, got %#v", headers)
	}
	assertRuntimeUserCount(t, inbound.Id, 1)

	expiredAt := resetAt - 60
	expiredDueReset := resetAt - 5
	totalUpBeforeExpiredReset := saved.TotalUp
	totalDownBeforeExpiredReset := saved.TotalDown
	if err := db.Model(model.Client{}).Where("id = ?", saved.Id).Updates(map[string]interface{}{
		"expiry":     expiredAt,
		"enable":     false,
		"up":         volume + 5,
		"down":       int64(9),
		"next_reset": expiredDueReset,
	}).Error; err != nil {
		t.Fatal(err)
	}
	tx = db.Begin()
	expiredInboundIds, err := (&service.ClientService{}).ResetClients(tx, resetAt)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit().Error; err != nil {
		t.Fatal(err)
	}
	if len(expiredInboundIds) != 0 {
		t.Fatalf("traffic reset must not restore expired accounts into runtime config, got %#v", expiredInboundIds)
	}
	if err := db.Where("id = ?", saved.Id).First(&saved).Error; err != nil {
		t.Fatal(err)
	}
	if saved.Expiry != expiredAt {
		t.Fatalf("traffic reset must not extend account expiry, got %d want %d", saved.Expiry, expiredAt)
	}
	if saved.Enable {
		t.Fatal("expired account should remain disabled after traffic cycle reset")
	}
	if service.IsClientActive(&saved, resetAt) {
		t.Fatal("expired account must remain inactive after traffic cycle reset")
	}
	if saved.Up != 0 || saved.Down != 0 {
		t.Fatalf("expired account traffic cycle reset should still clear counters, got up=%d down=%d", saved.Up, saved.Down)
	}
	if saved.TotalUp != totalUpBeforeExpiredReset+volume+5 || saved.TotalDown != totalDownBeforeExpiredReset+9 {
		t.Fatalf("expired account reset should keep accounting totals, got totalUp=%d totalDown=%d", saved.TotalUp, saved.TotalDown)
	}
	if _, _, err := subSvc.GetSubs("token-cycle"); err == nil {
		t.Fatal("expired account subscription must remain rejected after traffic cycle reset")
	}

	var storageType string
	if err := db.Raw("select typeof(links) from clients where id = ?", saved.Id).Scan(&storageType).Error; err != nil {
		t.Fatal(err)
	}
	if storageType != "blob" {
		t.Fatalf("clients.links must remain BLOB/json.RawMessage compatible, got %q", storageType)
	}
}

func setSubTestSetting(t *testing.T, key string, value string) {
	t.Helper()
	setting := model.Setting{Key: key}
	if err := database.GetDB().Where("key = ?", key).Assign(model.Setting{Value: value}).FirstOrCreate(&setting).Error; err != nil {
		t.Fatal(err)
	}
}

func createRealityInbound(t *testing.T) model.Inbound {
	t.Helper()
	db := database.GetDB()
	tlsConfig := model.Tls{
		Name: "reality-template-cycle",
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
	return inbound
}

func clientPayload(id uint, inboundId uint, expiry int64, volume int64, enable bool) map[string]interface{} {
	payload := map[string]interface{}{
		"enable":            enable,
		"name":              "alice",
		"subscriptionToken": "token-recover",
		"remark":            "alice",
		"inbounds":          []uint{inboundId},
		"links":             []map[string]string{},
		"volume":            volume,
		"expiry":            expiry,
		"up":                0,
		"down":              0,
		"config": map[string]map[string]string{
			"vless": {
				"uuid": "11111111-1111-4111-8111-111111111111",
				"flow": "xtls-rprx-vision",
			},
		},
	}
	if id > 0 {
		payload["id"] = id
	}
	return payload
}

func mustMarshal(t *testing.T, v interface{}) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func assertRuntimeUserCount(t *testing.T, inboundId uint, want int) {
	t.Helper()
	configs, err := (&service.InboundService{}).GetAllConfig(database.GetDB())
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range configs {
		var inbound map[string]interface{}
		if err := json.Unmarshal(raw, &inbound); err != nil {
			t.Fatal(err)
		}
		if inbound["tag"] != "vless-reality" {
			continue
		}
		if inbound["users"] == nil && want == 0 {
			return
		}
		users, ok := inbound["users"].([]interface{})
		if !ok {
			t.Fatalf("runtime inbound users has unexpected type: %#v", inbound["users"])
		}
		if len(users) != want {
			t.Fatalf("runtime inbound should contain %d active users, got %d: %#v", want, len(users), users)
		}
		return
	}
	t.Fatalf("runtime inbound %d was not generated", inboundId)
}

func containsUint(values []uint, needle uint) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
