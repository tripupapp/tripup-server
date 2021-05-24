package notification

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
)

type OneSignal struct {
    AppID 	string
    APIKey 	string
}

func (onesignal OneSignal) Notify(userIDs []string, notification Notification, additionalData *map[string]string) (error) {
    data := map[string]string{"signal": notification.signal}
    if additionalData != nil {
        for key, value := range *additionalData {
            data[key] = value
        }
    }

    var contents map[string]interface{}
    if !notification.silent {
        contents = make(map[string]interface{})
        contents["en"] = notification.signal
    }

    notificationPayload, err := json.Marshal(map[string]interface{} {
        "app_id": onesignal.AppID,
        "include_external_user_ids": userIDs,
        "data": data,
        "contents": contents,
        "content_available": true,
    })
    if err != nil {
        return err
    }

    notificationRequest, err := http.NewRequest("POST", "https://onesignal.com/api/v1/notifications", bytes.NewBuffer(notificationPayload))
    if err != nil {
        return err
    }
    notificationRequest.Header.Set("Content-Type", "application/json; charset=utf-8")
    notificationRequest.Header.Set("Authorization", "Basic " + onesignal.APIKey)

    httpClient := &http.Client{}
    notificationResponse, err := httpClient.Do(notificationRequest)
    if err != nil {
        return err
    }
    defer notificationResponse.Body.Close()
    if notificationResponse.StatusCode != http.StatusOK {
        body, err := ioutil.ReadAll(notificationResponse.Body)
        if err != nil {
            return err
        }
        return errors.New(string(body))
    }
    return nil
}
