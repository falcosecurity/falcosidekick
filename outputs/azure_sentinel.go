// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
    "bytes"
    "crypto/hmac"
    "crypto/sha256"
    "crypto/tls"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "net/http"
    "time"

    "go.opentelemetry.io/otel/attribute"

    "github.com/falcosecurity/falcosidekick/internal/pkg/utils"
    "github.com/falcosecurity/falcosidekick/types"
)

// getClientTransport returns a proper http transport based on the TLS configuration
func getClientTransport(checkCert bool) *http.Transport {
    return &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: !checkCert,
        },
    }
}

type azureSentinelPayload struct {
    Rule     string                 `json:"Rule"`
    Priority string                 `json:"Priority"`
    Source   string                 `json:"Source"`
    Output   string                 `json:"Output"`
    Time     string                 `json:"Time"`
    Hostname string                 `json:"Hostname,omitempty"`
    Fields   map[string]interface{} `json:"-"`
}

func newAzureSentinelPayload(falcopayload types.FalcoPayload) []map[string]interface{} {
    // Create the base payload
    row := map[string]interface{}{
        "Rule":     falcopayload.Rule,
        "Priority": falcopayload.Priority.String(),
        "Source":   falcopayload.Source,
        "Output":   falcopayload.Output,
        "Time":     falcopayload.Time.Format(time.RFC3339),
    }
    
    // Add hostname if available
    if falcopayload.Hostname != "" {
        row["Hostname"] = falcopayload.Hostname
    }

    // Add all output fields to the payload
    if len(falcopayload.OutputFields) > 0 {
        for k, v := range falcopayload.OutputFields {
            row[k] = v
        }
    }

    return []map[string]interface{}{row}
}

// AzureSentinelPost sends event to Azure Sentinel
func (c *Client) AzureSentinelPost(falcopayload types.FalcoPayload) {
    c.Stats.AzureSentinel.Add(Total, 1)

    workspaceID := c.Config.AzureSentinel.WorkspaceID
    sharedKey := c.Config.AzureSentinel.SharedKey
    tableName := c.Config.AzureSentinel.TableName

    payload := newAzureSentinelPayload(falcopayload)
    body, err := json.Marshal(payload)
    if err != nil {
        go c.CountMetric(Outputs, 1, []string{"output:azuresentinel", "status:error"})
        c.Stats.AzureSentinel.Add(Error, 1)
        c.PromStats.Outputs.With(map[string]string{"destination": "azure_sentinel", "status": Error}).Inc()
        c.OTLPMetrics.Outputs.With(attribute.String("destination", "azure_sentinel"),
            attribute.String("status", Error)).Inc()
        utils.Log(utils.ErrorLvl, c.OutputType, fmt.Sprintf("Error marshaling payload: %v", err))
        return
    }

    // Create API signature for Azure Sentinel
    date := time.Now().UTC().Format(http.TimeFormat)
    contentLength := len(body)
    stringToSign := fmt.Sprintf("POST\n%d\napplication/json\nx-ms-date:%s\n/api/logs", contentLength, date)

    keyBytes, _ := base64.StdEncoding.DecodeString(sharedKey)
    mac := hmac.New(sha256.New, keyBytes)
    mac.Write([]byte(stringToSign))
    signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
    authHeader := fmt.Sprintf("SharedKey %s:%s", workspaceID, signature)

    // Create and send request
    url := fmt.Sprintf("https://%s.ods.opinsights.azure.com/api/logs?api-version=2016-04-01", workspaceID)
    req, err := http.NewRequest("POST", url, bytes.NewReader(body))
    if err != nil {
        go c.CountMetric(Outputs, 1, []string{"output:azuresentinel", "status:error"})
        c.Stats.AzureSentinel.Add(Error, 1)
        c.PromStats.Outputs.With(map[string]string{"destination": "azure_sentinel", "status": Error}).Inc()
        c.OTLPMetrics.Outputs.With(attribute.String("destination", "azure_sentinel"),
            attribute.String("status", Error)).Inc()
        utils.Log(utils.ErrorLvl, c.OutputType, fmt.Sprintf("Error creating request: %v", err))
        return
    }

    req.Header.Add("Content-Type", "application/json")
    req.Header.Add("Log-Type", tableName)
    req.Header.Add("x-ms-date", date)
    req.Header.Add("Authorization", authHeader)

    httpClient := http.Client{
        Transport: getClientTransport(c.Config.AzureSentinel.CheckCert),
        Timeout:   time.Duration(c.Config.AzureSentinel.MaxConcurrentRequests) * time.Second,
    }
    
    resp, err := httpClient.Do(req)
    if (err != nil) {
        go c.CountMetric(Outputs, 1, []string{"output:azuresentinel", "status:error"})
        c.Stats.AzureSentinel.Add(Error, 1)
        c.PromStats.Outputs.With(map[string]string{"destination": "azure_sentinel", "status": Error}).Inc()
        c.OTLPMetrics.Outputs.With(attribute.String("destination", "azure_sentinel"),
            attribute.String("status", Error)).Inc()
        utils.Log(utils.ErrorLvl, c.OutputType, fmt.Sprintf("Error sending event: %v", err))
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        go c.CountMetric(Outputs, 1, []string{"output:azuresentinel", "status:error"})
        c.Stats.AzureSentinel.Add(Error, 1)
        c.PromStats.Outputs.With(map[string]string{"destination": "azure_sentinel", "status": Error}).Inc()
        c.OTLPMetrics.Outputs.With(attribute.String("destination", "azure_sentinel"),
            attribute.String("status", Error)).Inc()
        utils.Log(utils.ErrorLvl, c.OutputType, fmt.Sprintf("HTTP response error (%d): %s", resp.StatusCode, resp.Status))
        return
    }

    go c.CountMetric(Outputs, 1, []string{"output:azuresentinel", "status:ok"})
    c.Stats.AzureSentinel.Add(OK, 1)
    c.PromStats.Outputs.With(map[string]string{"destination": "azure_sentinel", "status": OK}).Inc()
    c.OTLPMetrics.Outputs.With(attribute.String("destination", "azure_sentinel"),
        attribute.String("status", OK)).Inc()
}
