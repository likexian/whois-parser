/*
 * Go module for whois info parser
 * https://www.likexian.com/
 *
 * Copyright 2014-2019, Li Kexian
 * Released under the Apache License, Version 2.0
 *
 */

package whois_parser


import (
    "strings"
    "io/ioutil"
)


func ReadFile(file string) (str string, err error) {
    tmpResult, err := ioutil.ReadFile(file)
    if err != nil {
        return
    }
    return string(tmpResult), nil
}


func WriteFile(file string, data string) error {
    return ioutil.WriteFile(file, []byte(data), 0644)
}


func IsNotFound(data string) (result bool) {
    data = strings.ToLower(data)
    return strings.Contains(data, "no found") || strings.Contains(data, "no match") ||
        strings.Contains(data, "not found") || strings.Contains(data, "not match") ||
        strings.Contains(data, "no entries found") || strings.Contains(data, "no data found") ||
        strings.Contains(data, "not registered") || strings.Contains(data, "is free") ||
        strings.Contains(data, "not available for registration")
}


func IsLimitExceeded(data string) (result bool) {
    data = strings.ToLower(data)
    return strings.Contains(data, "limit exceeded")
}


func ClearName(key string) (string) {
    if strings.Contains(key, "(") {
        key = strings.Split(key, "(")[0]
    }

    key = strings.Replace(key, "-", " ", -1)
    key = strings.Replace(key, "_", " ", -1)
    key = strings.Replace(key, "/", " ", -1)
    key = strings.Replace(key, "\\", " ", -1)
    key = strings.Replace(key, "'", " ", -1)
    key = strings.Replace(key, ".", " ", -1)

    key = strings.TrimSpace(key)
    key = strings.ToLower(key)

    return key
}


func FindKeyName(key string) (name string) {
    key = ClearName(key)
    if v, ok := name_rule[key]; ok {
        return v
    }

    return ""
}


func RemoveDuplicateField(data string) string {
    var newFields []string
    for _, v := range strings.Split(data, ",") {
        if v == "" {
            continue
        }
        if !StringInArray(newFields, v) {
            newFields = append(newFields, v)
        }
    }
    return strings.Join(newFields, ",")
}


func StringInArray(array []string, find string) bool {
    for _, v := range array {
        if v == find {
            return true
        }
    }
    return false
}


func FixNameServers(nservers string) string {
    servers := strings.Split(nservers, ",")
    for k, v := range servers {
        names := strings.Split(strings.TrimSpace(v), " ")
        servers[k] = strings.Trim(names[0], ".")
    }
    return strings.Join(servers, ",")
}
