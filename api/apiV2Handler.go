package api

import (
	"crypto/subtle"
	"encoding/json"
	"sync"
	"time"

	"github.com/alireza0/s-ui/logger"
	"github.com/alireza0/s-ui/util/common"

	"github.com/gin-gonic/gin"
)

type TokenInMemory struct {
	Token    string
	Expiry   int64
	Username string
}

type APIv2Handler struct {
	ApiService
	tokensMu sync.RWMutex
	tokens   []TokenInMemory
}

func NewAPIv2Handler(g *gin.RouterGroup) *APIv2Handler {
	a := &APIv2Handler{}
	a.ReloadTokens()
	a.initRouter(g)
	return a
}

func (a *APIv2Handler) initRouter(g *gin.RouterGroup) {
	g.Use(func(c *gin.Context) {
		a.checkToken(c)
	})
	g.POST("/:postAction", a.postHandler)
	g.GET("/:getAction", a.getHandler)
}

func (a *APIv2Handler) postHandler(c *gin.Context) {
	action := c.Param("postAction")

	switch action {
	case "save":
		a.rejectHighRiskTokenAction(c, action)
	case "restartApp":
		a.rejectHighRiskTokenAction(c, action)
	case "restartSb":
		a.rejectHighRiskTokenAction(c, action)
	case "resetTraffic":
		a.rejectHighRiskTokenAction(c, action)
	case "linkConvert":
		a.ApiService.LinkConvert(c)
	case "subConvert":
		a.rejectHighRiskTokenAction(c, action)
	case "importdb":
		a.rejectHighRiskTokenAction(c, action)
	case "getCertPing":
		a.rejectHighRiskTokenAction(c, action)
	default:
		jsonMsg(c, "failed", common.NewError("unknown action: ", action))
	}
}

func (a *APIv2Handler) getHandler(c *gin.Context) {
	action := c.Param("getAction")

	switch action {
	case "load":
		a.ApiService.LoadData(c)
	case "inbounds", "outbounds", "endpoints", "services", "tls", "clients", "config":
		err := a.ApiService.LoadPartialData(c, []string{action})
		if err != nil {
			jsonMsg(c, action, err)
		}
		return
	case "users":
		a.ApiService.GetUsers(c)
	case "settings":
		a.ApiService.GetSettings(c)
	case "stats":
		a.ApiService.GetStats(c)
	case "status":
		a.ApiService.GetStatus(c)
	case "onlines":
		a.ApiService.GetOnlines(c)
	case "logs":
		a.ApiService.GetLogs(c)
	case "changes":
		a.ApiService.CheckChanges(c)
	case "keypairs":
		a.ApiService.GetKeypairs(c)
	case "getdb":
		a.rejectHighRiskTokenAction(c, action)
	case "checkOutbound":
		a.rejectHighRiskTokenAction(c, action)
	default:
		jsonMsg(c, "failed", common.NewError("unknown action: ", action))
	}
}

func (a *APIv2Handler) findUsername(c *gin.Context) string {
	token := c.Request.Header.Get("Token")
	if token == "" {
		return ""
	}
	now := time.Now().Unix()
	a.tokensMu.RLock()
	defer a.tokensMu.RUnlock()
	for _, t := range a.tokens {
		if t.Expiry > 0 && t.Expiry < now {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(t.Token), []byte(token)) == 1 {
			return t.Username
		}
	}
	return ""
}

func (a *APIv2Handler) checkToken(c *gin.Context) {
	username := a.findUsername(c)
	if username != "" {
		c.Next()
		return
	}
	jsonMsg(c, "", common.NewError("invalid token"))
	c.Abort()
}

func (a *APIv2Handler) ReloadTokens() {
	tokens, err := a.ApiService.LoadTokens()
	if err == nil {
		var newTokens []TokenInMemory
		err = json.Unmarshal(tokens, &newTokens)
		if err != nil {
			logger.Error("unable to load tokens: ", err)
		}
		a.tokensMu.Lock()
		a.tokens = newTokens
		a.tokensMu.Unlock()
	} else {
		logger.Error("unable to load tokens: ", err)
	}
}

func (a *APIv2Handler) rejectHighRiskTokenAction(c *gin.Context, action string) {
	jsonMsg(c, "failed", common.NewError("api token is not allowed to call high-risk action: ", action))
}
