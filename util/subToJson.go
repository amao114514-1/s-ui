package util

import (
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/alireza0/s-ui/logger"
	"github.com/alireza0/s-ui/util/common"
)

type externalSubCacheEntry struct {
	data      string
	expiresAt time.Time
}

var externalSubCache = struct {
	sync.Mutex
	items map[string]externalSubCacheEntry
}{items: make(map[string]externalSubCacheEntry)}

func GetExternalLink(url string) string {
	body, err := FetchExternalURL(url, defaultExternalFetchLimit)
	if err != nil {
		logger.Warning("sub: Error fetching external subscription:", err)
		return ""
	}

	data := StrOrBase64Encoded(body)
	return data
}

func GetExternalLinkCached(url string) string {
	now := time.Now()
	externalSubCache.Lock()
	if entry, ok := externalSubCache.items[url]; ok && now.Before(entry.expiresAt) {
		externalSubCache.Unlock()
		return entry.data
	}
	externalSubCache.Unlock()

	data := GetExternalLink(url)
	if data == "" {
		return ""
	}

	externalSubCache.Lock()
	externalSubCache.items[url] = externalSubCacheEntry{
		data:      data,
		expiresAt: now.Add(5 * time.Minute),
	}
	externalSubCache.Unlock()
	return data
}

func GetExternalSub(url string) ([]map[string]interface{}, error) {
	return parseExternalSub(url, GetExternalLink)
}

func GetExternalSubCached(url string) ([]map[string]interface{}, error) {
	return parseExternalSub(url, GetExternalLinkCached)
}

func parseExternalSub(url string, fetch func(string) string) ([]map[string]interface{}, error) {
	var err error
	var result []map[string]interface{}

	if len(url) == 0 {
		return nil, common.NewError("no url")
	}

	data := fetch(url)
	if len(data) == 0 {
		return nil, common.NewError("no result")
	}

	// if the data is a JSON object
	if strings.HasPrefix(data, "{") && strings.HasSuffix(data, "}") {
		var jsonData map[string]interface{}
		err = json.Unmarshal([]byte(data), &jsonData)
		if err != nil {
			logger.Warning("sub: Error unmarshalling JSON:", err)
			return nil, err
		}
		outbounds, ok := jsonData["outbounds"].([]any)
		if !ok {
			logger.Warning("sub: Error getting outbounds:", err)
			return nil, err
		}
		for _, outbound := range outbounds {
			outboundMap, ok := outbound.(map[string]interface{})
			if ok && len(outboundMap) > 0 {
				oType, _ := outboundMap["type"].(string)
				switch oType {
				case "urltest":
				case "direct":
				case "selector":
				case "block":
					continue
				default:
					result = append(result, outboundMap)
				}
			}
		}
		if len(result) == 0 {
			return nil, common.NewError("no result")
		}
		return result, nil
	} else {
		// if data is a text
		links := strings.Split(data, "\n")
		for _, link := range links {
			linkToJson, _, err := GetOutbound(link, 0)
			if err == nil {
				result = append(result, *linkToJson)
			}
		}
	}
	if len(result) == 0 {
		return nil, common.NewError("no result")
	}
	return result, nil
}
