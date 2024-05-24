package domain

type WorkFlowResponseData struct {
	Result       interface{} `json:"result"`
	WorkflowID   string      `json:"workflowId"`
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
	CorrelationID   string               `json:"correlationid"`
	Stream          string               `json:"stream"`
}
