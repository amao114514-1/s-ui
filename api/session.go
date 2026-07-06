package api

import (
	"encoding/gob"
	"net/http"
	"time"

	"github.com/alireza0/s-ui/database"
	"github.com/alireza0/s-ui/database/model"
	"github.com/alireza0/s-ui/util/common"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

const (
	loginUser = "LOGIN_USER"
	csrfToken = "CSRF_TOKEN"
	loginSessionVersion = "LOGIN_SESSION_VERSION"
	loginAt = "LOGIN_AT"
)

func init() {
	gob.Register(model.User{})
}

func SetLoginUser(c *gin.Context, userName string, maxAge int) error {
	options := sessions.Options{
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecureRequest(c),
		SameSite: http.SameSiteLaxMode,
	}
	if maxAge > 0 {
		options.MaxAge = maxAge * 60
	}

	s := sessions.Default(c)
	s.Set(loginUser, userName)
	s.Set(loginSessionVersion, getUserSessionVersion(userName))
	s.Set(loginAt, time.Now().Unix())
	s.Set(csrfToken, common.Random(32))
	s.Options(options)

	return s.Save()
}

func SetMaxAge(c *gin.Context) error {
	s := sessions.Default(c)
	s.Options(sessions.Options{
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecureRequest(c),
		SameSite: http.SameSiteLaxMode,
	})
	return s.Save()
}

func GetLoginUser(c *gin.Context) string {
	s := sessions.Default(c)
	obj := s.Get(loginUser)
	if obj == nil {
		return ""
	}
	objStr, ok := obj.(string)
	if !ok {
		return ""
	}
	return objStr
}

func IsLogin(c *gin.Context) bool {
	username := GetLoginUser(c)
	if username == "" {
		return false
	}
	s := sessions.Default(c)
	sessionVersion, ok := s.Get(loginSessionVersion).(int64)
	if !ok {
		return false
	}
	return sessionVersion == getUserSessionVersion(username)
}

func GetCSRFToken(c *gin.Context) string {
	s := sessions.Default(c)
	obj := s.Get(csrfToken)
	token, ok := obj.(string)
	if !ok {
		return ""
	}
	return token
}

func IsRecentLogin(c *gin.Context, maxAge time.Duration) bool {
	s := sessions.Default(c)
	loginUnix, ok := s.Get(loginAt).(int64)
	if !ok || loginUnix <= 0 {
		return false
	}
	return time.Since(time.Unix(loginUnix, 0)) <= maxAge
}

func ClearSession(c *gin.Context) {
	s := sessions.Default(c)
	s.Clear()
	s.Options(sessions.Options{
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isSecureRequest(c),
		SameSite: http.SameSiteLaxMode,
	})
	s.Save()
}

func isSecureRequest(c *gin.Context) bool {
	if c.Request.TLS != nil {
		return true
	}
	return c.GetHeader("X-Forwarded-Proto") == "https"
}

func getUserSessionVersion(username string) int64 {
	db := database.GetDB()
	if db == nil {
		return 0
	}
	var version int64
	if err := db.Model(model.User{}).Where("username = ?", username).Select("session_version").Scan(&version).Error; err != nil {
		return -1
	}
	return version
}
