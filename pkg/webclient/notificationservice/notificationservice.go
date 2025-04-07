package notificationservice

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-http-utils/headers"
	"github.com/gorilla/websocket"

	"github.com/Venafi/vcert/v5/pkg/domain"
	"github.com/Venafi/vcert/v5/pkg/util"
)

type NotificationServiceClient struct {
	baseURL     string
	accessToken string
	apiKey      string
}

func NewNotificationServiceClient(baseURL string, accessToken string, apiKey string) *NotificationServiceClient {
	return &NotificationServiceClient{
		baseURL:     baseURL,
		accessToken: accessToken,
		apiKey:      apiKey,
	}
}

func (ns *NotificationServiceClient) Subscribe(wsClientId string) (*websocket.Conn, error) {

	_, host, found := strings.Cut(ns.baseURL, "https://")
	if !found {
		return nil, fmt.Errorf("failed to parse baseURL")
	}

	if strings.HasSuffix(host, "/") && len(host) > 0 {
		host = host[:len(host)-1]
	}

	notificationsUrl := url.URL{Scheme: "wss", Host: host, Path: fmt.Sprintf("ws/notificationclients/%s", wsClientId)}
	httpHeader := http.Header{}
	if ns.accessToken != "" {
		httpHeader = http.Header{headers.Authorization: {fmt.Sprintf("%s %s", util.OauthTokenType, ns.accessToken)}}
	} else if ns.apiKey != "" {
		httpHeader = http.Header{util.HeaderTpplApikey: {ns.apiKey}}
	}

	// nolint:bodyclose // TODO: figure out better way to close the body reponse so it is detected by the linter
	wsConn, resp, err := websocket.DefaultDialer.Dial(notificationsUrl.String(), httpHeader)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		tempErr := Body.Close()
		if tempErr != nil {
			err = tempErr
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("failed switch protocols")
	}
	log.Print("successfully switched to websocket connection")

	time.Sleep(5 * time.Second)
	return wsConn, nil
}

func (ns *NotificationServiceClient) ReadResponse(wsConn *websocket.Conn) (
	*domain.WorkflowResponse, error) {
	_, msg, err := wsConn.ReadMessage()
	if err != nil {
		return nil, err
	}

	defer func() {
		_ = wsConn.Close()
	}()
	log.Printf("<---- Workflow Response:\n%s", msg)

	workflowResponse := domain.WorkflowResponse{}
	err = json.Unmarshal(msg, &workflowResponse)
	if err != nil {
		log.Printf("failed to unmarshal response %s", err.Error())
		return nil, err
	}

	return &workflowResponse, nil
}
