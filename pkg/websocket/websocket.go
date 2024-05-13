package websocket

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Venafi/vcert/v5/pkg/util"
	"github.com/go-http-utils/headers"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

// WebsocketOptions command line options group that apply to all websockets
type WebsocketOptions struct {
	PingPeriod     time.Duration
	PongWait       time.Duration
	MaxMessageSize int64
	WriteWait      time.Duration
}

type WebsocketClient struct {
	wsOptions *WebsocketOptions
	WsConn    *websocket.Conn
	messages  chan []byte
	Ctx       context.Context    // corresponds to ws session, so ok in struct
	Cancel    context.CancelFunc // as above
}

type WorkFlowResponseData struct {
	Result       interface{} `json:"result"`
	WorkflowId   string      `json:"workflowId"`
	WorkflowName string      `json:"workflowName"`
	WsClientId   string      `json:"wsClientId"`
}

type WorkflowResponse struct {
	SpecVersion     string               `json:"specversion"`
	Id              string               `json:"id"`
	Source          string               `json:"source"`
	Type            string               `json:"type"`
	Subject         string               `json:"subject"`
	DataContentType string               `json:"datacontenttype"`
	Time            string               `json:"time"`
	Data            WorkFlowResponseData `json:"data"`
	EventKind       string               `json:"eventkind"`
	EventResource   string               `json:"eventresource"`
	Recipient       string               `json:"recipient"`
	CorrelationId   string               `json:"correlationid"`
	Stream          string               `json:"stream"`
}

func (wsc *WebsocketClient) ReadMessages() (*WorkflowResponse, error) {
	defer func() {
		log.Printf("ws read action defer")
		wsc.Cancel()
	}()

	wsc.WsConn.SetReadLimit(wsc.wsOptions.MaxMessageSize)
	_ = wsc.WsConn.SetReadDeadline(time.Now().Add(wsc.wsOptions.PongWait))
	wsc.WsConn.SetPongHandler(func(string) error {
		_ = wsc.WsConn.SetReadDeadline(time.Now().Add(wsc.wsOptions.PongWait))

		log.Printf("ws read action pong")
		return nil
	})

	_, msg, err := wsc.WsConn.ReadMessage()
	if err != nil {
		if websocket.IsUnexpectedCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
			log.Printf("unexpected close %v", err)
		}
		return nil, err
	}
	prettified := msg
	ar := WorkflowResponse{}
	err = json.Unmarshal(msg, &ar)
	if err != nil {
		log.Printf("failed to unmarshal response %v", err)
	} else {
		prettified, err = json.MarshalIndent(ar, "", "    ")
		if err != nil {
			log.Println(err.Error())
		}
	}

	log.Printf("<---- Workflow Response:\n%s", prettified)
	return &ar, nil

}

func (wsc *WebsocketClient) writeMessages() {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(wsc.wsOptions.PingPeriod)
	defer func() {
		signal.Stop(interrupt)
		ticker.Stop()
	}()

	for {
		select {
		case <-wsc.Ctx.Done():
			log.Print("ws write action done")
			return
		case <-ticker.C:
			err := wsc.WsConn.SetWriteDeadline(time.Now().Add(wsc.wsOptions.WriteWait))
			if err != nil {
				log.Printf("failed to set a write deadline %v", err)
				return
			}

			if err := wsc.WsConn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Printf("failed to write a message %v", err)
				return
			}

			log.Print("ws write action ping")
		case <-interrupt:
			log.Print("os interrupt")

			// cleanly close the connection by sending a close message and then waiting for the server to close the connection
			err := wsc.WsConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				return
			}

			select {
			case <-wsc.Ctx.Done():
			case <-time.After(time.Second):
			}
			return
		}
	}
}

func Subscribe(apiKey string, accessToken string, baseUrl string, wsClientId string) (*websocket.Conn, error) {

	_, host, found := strings.Cut(baseUrl, "https://")
	if !found {
		return nil, fmt.Errorf("failed to parse baseurl")
	}

	if strings.HasSuffix(host, "/") && len(host) > 0 {
		host = host[:len(host)-1]
	}

	notificationsUrl := url.URL{Scheme: "wss", Host: host, Path: fmt.Sprintf("ws/notificationclients/%s", wsClientId)}
	httpHeader := http.Header{}
	if accessToken != "" {
		httpHeader = http.Header{headers.Authorization: {fmt.Sprintf("%s %s", util.OauthTokenType, accessToken)}}
	} else if apiKey != "" {
		httpHeader = http.Header{util.HeaderTpplApikey: {apiKey}}
	}

	wsConn, resp, err := websocket.DefaultDialer.Dial(notificationsUrl.String(), httpHeader)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("failed switch protocols")
	}
	log.Print("successfully switched to websocket connection")

	var wsc = &WebsocketClient{
		WsConn: wsConn,
	}
	wsc.Ctx, wsc.Cancel = context.WithCancel(context.Background())

	time.Sleep(5 * time.Second)
	return wsConn, nil
}

func ReadResponse(wsConn *websocket.Conn) (*WorkflowResponse, error) {

	_, msg, err := wsConn.ReadMessage()
	if err != nil {
		return nil, err
	}

	defer func() {
		_ = wsConn.Close()
	}()

	wfResponse := msg
	ar := WorkflowResponse{}
	err = json.Unmarshal(msg, &ar)
	if err != nil {
		log.Printf("failed to unmarshal response %v", err)
	} else {
		wfResponse, err = json.MarshalIndent(ar, "", "    ")
		if err != nil {
			log.Println(err.Error())
		}
	}
	log.Printf("<---- Workflow Response:\n%s", wfResponse)

	if wfResponse == nil {
		return nil, err
	}
	return &ar, nil
}
