package dto

type Fingerprint struct {
	MachineID       string `json:"machine_id"`
	Hostname        string `json:"hostname"`
	OSID            string `json:"os_id"`
	OSVersion       string `json:"os_version"`
	CloudInstanceID string `json:"cloud_instance_id,omitempty"`
	IPAddress       string `json:"ip_address,omitempty"` // 추가
}

type EnrollRequest struct {
	HostID        string       `json:"host_id"`
	RequestedEnv  string       `json:"requested_env,omitempty"`
	RequestedRole string       `json:"requested_role,omitempty"`
	InstallUUID   string       `json:"install_uuid"`
	Fingerprint   *Fingerprint `json:"fingerprint"`
	CSRPEM        string       `json:"csr_pem"`
}

type EnrollResult string

const (
	EnrollResultApproved EnrollResult = "approved"
	EnrollResultPending  EnrollResult = "pending"
	EnrollResultRejected EnrollResult = "rejected"
)

type EnrollResponse struct {
	Result         EnrollResult `json:"result"`
	ReasonCode     string       `json:"reason_code"`
	Message        string       `json:"message"`
	RequestID      string       `json:"request_id"`
	AgentID        string       `json:"agent_id,omitempty"`
	CertificatePEM string       `json:"certificate_pem,omitempty"`

	AssignedEnv  string `json:"assigned_env,omitempty"`
	AssignedRole string `json:"assigned_role,omitempty"`
}

type EnrollStatusResponse struct {
	Result         EnrollResult `json:"result"`
	ReasonCode     string       `json:"reason_code"`
	Message        string       `json:"message"`
	RequestID      string       `json:"request_id"`
	AgentID        string       `json:"agent_id,omitempty"`
	CertificatePEM string       `json:"certificate_pem,omitempty"`

	AssignedEnv  string `json:"assigned_env,omitempty"`
	AssignedRole string `json:"assigned_role,omitempty"`
}
