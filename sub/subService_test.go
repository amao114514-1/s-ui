package sub

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alireza0/s-ui/database"
	"github.com/alireza0/s-ui/database/model"
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
