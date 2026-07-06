package database

import (
	"path/filepath"
	"testing"

	"github.com/alireza0/s-ui/database/model"
	"github.com/alireza0/s-ui/util"
)

func TestInitDBDoesNotCreateDefaultAdminPassword(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "s-ui.db")
	if err := InitDB(dbPath); err != nil {
		t.Fatal(err)
	}

	var user model.User
	if err := GetDB().Model(model.User{}).First(&user).Error; err != nil {
		t.Fatal(err)
	}
	if user.Username == "admin" && user.Password == "admin" {
		t.Fatal("default admin/admin credentials must not be created")
	}
	if !util.IsHashedPassword(user.Password) {
		t.Fatalf("initial password should be stored as a hash, got %q", user.Password)
	}
}
