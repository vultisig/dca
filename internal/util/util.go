package util

func GetStr(cfg map[string]any, key string) string {
	var res string
	if val, ok := cfg[key]; ok && val != nil {
		res, _ = val.(string)
	}
	return res
}

func IfEmptyElse(str string, def string) string {
	if str == "" {
		return def
	}
	return str
}
