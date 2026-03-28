package enroll

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	bootstrap_tls "github.com/suhyeon514/eBPF_Project/internal/bootstrap/tls"
	"github.com/suhyeon514/eBPF_Project/internal/config"
	"github.com/suhyeon514/eBPF_Project/internal/transport/dto"
)

type Client struct {
	cfg        *config.BootstrapConfig
	httpClient *http.Client
}

func NewClient(cfg *config.BootstrapConfig) (*Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("bootstrap config is nil")
	}

	httpClient, err := bootstrap_tls.NewBootstrapHTTPClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create bootstrap http client: %w", err)
	}

	return &Client{
		cfg:        cfg,
		httpClient: httpClient,
	}, nil
}

func (c *Client) RequestEnrollment(
	ctx context.Context,
	req dto.EnrollRequest,
) (*dto.EnrollResponse, error) {
	if strings.TrimSpace(req.HostID) == "" {
		return nil, fmt.Errorf("enroll request host_id is empty")
	}
	if strings.TrimSpace(req.InstallUUID) == "" {
		return nil, fmt.Errorf("enroll request install_uuid is empty")
	}
	if req.Fingerprint == nil {
		return nil, fmt.Errorf("enroll request fingerprint is nil")
	}
	if strings.TrimSpace(req.CSRPEM) == "" {
		return nil, fmt.Errorf("enroll request csr_pem is empty")
	}

	endpoint := c.cfg.Server.BaseURL + c.cfg.Server.EnrollRequestPath

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal enroll request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("create http request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("send enroll request: %w", err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read enroll response body: %w", err)
	}

	var resp dto.EnrollResponse
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return nil, fmt.Errorf(
				"decode enroll response status=%d body=%s: %w",
				httpResp.StatusCode,
				string(respBody),
				err,
			)
		}
	}

	switch httpResp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted:
		if strings.TrimSpace(string(resp.Result)) == "" {
			switch httpResp.StatusCode {
			case http.StatusAccepted:
				resp.Result = dto.EnrollResultPending
			default:
				resp.Result = dto.EnrollResultApproved
			}
		}
		if strings.TrimSpace(resp.RequestID) == "" {
			return nil, fmt.Errorf("enroll response missing request_id")
		}
		return &resp, nil

	case http.StatusBadRequest,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusConflict,
		http.StatusUnprocessableEntity:
		if strings.TrimSpace(string(resp.Result)) == "" {
			resp.Result = dto.EnrollResultRejected
		}
		if strings.TrimSpace(resp.Message) == "" {
			resp.Message = fmt.Sprintf("server rejected enroll request with status=%d", httpResp.StatusCode)
		}
		return &resp, nil

	default:
		if strings.TrimSpace(resp.Message) != "" {
			return nil, fmt.Errorf("unexpected enroll response status=%d message=%s", httpResp.StatusCode, resp.Message)
		}
		return nil, fmt.Errorf("unexpected enroll response status=%d body=%s", httpResp.StatusCode, string(respBody))
	}
}

func (c *Client) GetEnrollmentStatus(
	ctx context.Context,
	requestID string,
) (*dto.EnrollStatusResponse, error) {
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return nil, fmt.Errorf("requestID is empty")
	}

	// enroll_status_path 예: /api/v1/enroll/requests
	endpoint := fmt.Sprintf("%s%s/%s", c.cfg.Server.BaseURL, c.cfg.Server.EnrollStatusPath, requestID)

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("create status request: %w", err)
	}

	httpReq.Header.Set("Accept", "application/json")

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("send status request: %w", err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read status response body: %w", err)
	}

	var resp dto.EnrollStatusResponse
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return nil, fmt.Errorf(
				"decode status response status=%d body=%s: %w",
				httpResp.StatusCode,
				string(respBody),
				err,
			)
		}
	}

	switch httpResp.StatusCode {
	case http.StatusOK:
		if strings.TrimSpace(string(resp.Result)) == "" {
			return nil, fmt.Errorf("status response missing result")
		}
		if strings.TrimSpace(resp.RequestID) == "" {
			resp.RequestID = requestID
		}
		return &resp, nil

	case http.StatusBadRequest,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusConflict,
		http.StatusUnprocessableEntity:
		if strings.TrimSpace(string(resp.Result)) == "" {
			resp.Result = dto.EnrollResultRejected
		}
		if strings.TrimSpace(resp.RequestID) == "" {
			resp.RequestID = requestID
		}
		return &resp, nil

	default:
		if strings.TrimSpace(resp.Message) != "" {
			return nil, fmt.Errorf("unexpected status response status=%d message=%s", httpResp.StatusCode, resp.Message)
		}
		return nil, fmt.Errorf("unexpected status response status=%d body=%s", httpResp.StatusCode, string(respBody))
	}
}
