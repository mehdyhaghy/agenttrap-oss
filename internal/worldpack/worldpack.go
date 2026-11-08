// Package worldpack defines the frozen, versioned persona content a spoke serves,
// and the signed envelope the hub uses to distribute it.
package worldpack

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// Pack is the persona world content. It is generated offline and frozen; the
// spoke never invents content at runtime.
type Pack struct {
	ID           string        `json:"id"`
	Version      string        `json:"version"`
	Company      Company       `json:"company"`
	Models       []Model       `json:"models"`
	Pricing      []Price       `json:"pricing"`
	Incidents    []Incident    `json:"status_incidents"`
	Team         Team          `json:"team"`
	ProviderKeys []ProviderKey `json:"provider_keys"`
	// ServiceAccounts are OAuth clients the team uses for automation. Their
	// secrets are canaries; only the decoy ops agent reveals them.
	ServiceAccounts []ServiceAccount `json:"service_accounts,omitempty"`
	OAuth           OAuth            `json:"oauth"`
	SSH             *SSH             `json:"ssh,omitempty"`
	Redis           *Redis           `json:"redis,omitempty"`
	Postgres        *Postgres        `json:"postgres,omitempty"`
	Cloud           *Cloud           `json:"cloud,omitempty"`
	Kube            *Kube            `json:"kube,omitempty"`
	Memory          *Memory          `json:"memory,omitempty"`
	RAG             *RAG             `json:"rag,omitempty"`
	// Lures are alternative wordings of honey descriptions; each address
	// sees one, and the hub measures which attracts agents.
	Lures     map[string][]Lure `json:"lures,omitempty"`
	Canaries  []CanarySpec      `json:"canaries"`
	Chain     []ChainStep       `json:"chain"`
	Replies   []string          `json:"replies"`
	Changelog []Incident        `json:"changelog"` // dated entries, same shape as incidents
}

type Company struct {
	Name         string `json:"name"`
	Domain       string `json:"domain"`
	Tagline      string `json:"tagline"`
	Description  string `json:"description"`
	Founded      int    `json:"founded"`
	HQ           string `json:"hq"`
	ServerHeader string `json:"server_header"`
	SupportEmail string `json:"support_email"`
	AnalyticsID  string `json:"analytics_id,omitempty"` // Google Analytics measurement ID, if any
}

type Model struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"` // chat, embedding
	Context int    `json:"context"`
	OwnedBy string `json:"owned_by"`
	Created int64  `json:"created"`
}

type Price struct {
	Model  string  `json:"model"`
	Input  float64 `json:"input_per_mtok"`
	Output float64 `json:"output_per_mtok"`
}

type Incident struct {
	Date  string `json:"date"`
	Title string `json:"title"`
	Body  string `json:"body"`
}

type Team struct {
	Name    string   `json:"name"`
	Plan    string   `json:"plan"`
	Members []Member `json:"members"`
}

type Member struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

// ProviderKey is a customer-configured upstream key shown in the console and
// MCP. Its secret value is the canary named by Slot.
type ProviderKey struct {
	Name      string `json:"name"`
	Provider  string `json:"provider"`
	BaseURL   string `json:"base_url"`
	Slot      string `json:"slot"`
	CreatedAt string `json:"created_at"`
	CreatedBy string `json:"created_by"`
}

// ServiceAccount is a team OAuth client for automation (client credentials).
type ServiceAccount struct {
	ClientID  string   `json:"client_id"`
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	Slot      string   `json:"slot"` // canary slot holding the client secret
	CreatedAt string   `json:"created_at"`
	CreatedBy string   `json:"created_by"`
}

// SSH is the persona's SSH host: a GPU node reached on port 22. Everything
// its shell shows comes from here. File contents may contain
// {{canary:<slot>}}, replaced by a per-exposure canary when the file is read.
type SSH struct {
	Banner   string            `json:"banner"` // server version string, e.g. SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.14
	Hostname string            `json:"hostname"`
	Kernel   string            `json:"kernel"` // uname -r
	MOTD     string            `json:"motd"`
	Users    []SSHUser         `json:"users"`
	Files    map[string]string `json:"files"` // absolute path -> content; directories are implied
	Procs    []string          `json:"procs"` // ps aux lines after the header
}

// SSHUser is an account on the SSH host. Its password is the canary in Slot.
type SSHUser struct {
	Name  string `json:"name"`
	UID   int    `json:"uid"`
	Home  string `json:"home"`
	Slot  string `json:"slot"`
	Group string `json:"group"`
}

// Redis is the persona's cache: an exposed, unauthenticated-looking Redis on
// port 6379. It never stores anything real; commands are answered from here
// and every command is recorded. Values may contain {{canary:<slot>}},
// replaced by a per-exposure canary when the key is read.
type Redis struct {
	Version string            `json:"version"` // e.g. 7.4.1
	Mode    string            `json:"mode"`    // standalone | cluster
	Role    string            `json:"role"`    // master | slave
	OS      string            `json:"os"`      // uname string in INFO
	Keys    map[string]string `json:"keys"`    // key -> value (SET/hash rendered as string)
	// Config answers CONFIG GET; dir and dbfilename matter because attackers
	// probe them before the classic CONFIG SET write-file technique.
	Config map[string]string `json:"config"`
}

// Postgres is the persona's database on port 5432: an exposed instance that
// asks for a cleartext password (so the attempt is captured) and, for a
// planted role and password, opens a read-only session answering canned
// queries from Queries. Cell values may contain {{canary:<slot>}}, minted per
// read. It runs no SQL and touches no real database.
type Postgres struct {
	Version     string          `json:"version"`      // e.g. 16.4
	VersionFull string          `json:"version_full"` // server_version / version() string
	Databases   []string        `json:"databases"`
	Users       []PostgresUser  `json:"users"`
	Queries     []PostgresQuery `json:"queries"`
}

// PostgresUser is a role whose password is the canary in Slot.
type PostgresUser struct {
	Name     string `json:"name"`
	Slot     string `json:"slot"`
	Database string `json:"database"` // default database for this role
}

// PostgresQuery is a canned result for a normalized query (lowercased, spaces
// collapsed, trailing ';' removed). Match is compared for equality first, then
// as a prefix.
type PostgresQuery struct {
	Match   string     `json:"match"`
	Columns []string   `json:"columns"`
	Rows    [][]string `json:"rows"`
	Tag     string     `json:"tag,omitempty"` // CommandComplete tag; default "SELECT <n>"
}

// Cloud is the persona's synthetic AWS account, reached by an SDK that a
// planted ~/.aws/config points at aws.<domain> (path-style S3). It answers
// STS, IAM, S3, Secrets Manager, SSM, EC2, EKS/ECS, CloudTrail and CloudWatch
// Logs from this content; it holds nothing real and calls no cloud provider.
// String values (object bodies, secret and parameter values) may contain
// {{canary:<slot>}}, minted per read like the other decoys.
type Cloud struct {
	Account   string `json:"account"`   // 12-digit account id
	Region    string `json:"region"`    // default region, e.g. eu-west-1
	Partition string `json:"partition"` // "aws" (defaults to aws)
	// AccessKeySlot is the canary slot for the long-term access key id planted
	// in ~/.aws/credentials. The access key id (not the secret, which never
	// leaves the client in a SigV4 signature) is what appears in a request's
	// Authorization header, so a use of it names the exact file read it came
	// from. STSKeySlot is the ASIA-prefixed temporary key id minted by STS
	// AssumeRole/GetSessionToken and IMDS. Both use distinctive AKIA/ASIA
	// prefixes; the secret keys are generated per hand-out and not tracked.
	AccessKeySlot string `json:"access_key_slot"`
	STSKeySlot    string `json:"sts_key_slot"`
	// Identity is the IAM principal the long-term key belongs to.
	Identity CloudIdentity `json:"identity"`
	// Instance is the EC2 instance this node runs on; IMDS answers from it.
	Instance CloudInstance `json:"instance"`
	Users    []CloudUser   `json:"users,omitempty"`
	Roles    []CloudRole   `json:"roles,omitempty"`
	Buckets  []CloudBucket `json:"buckets,omitempty"`
	Secrets  []CloudSecret `json:"secrets,omitempty"`
	// Parameters are SSM Parameter Store entries; SecureString values are traps.
	Parameters []CloudParameter `json:"parameters,omitempty"`
	// Clusters are EKS/ECS clusters returned by discovery calls.
	Clusters []CloudCluster `json:"clusters,omitempty"`
	// Trail is the synthetic CloudTrail history returned by LookupEvents.
	Trail []CloudTrailEvent `json:"trail,omitempty"`
	// LogGroups are the CloudWatch Logs groups returned by DescribeLogGroups.
	LogGroups []string `json:"log_groups,omitempty"`
}

// CloudIdentity is an IAM principal (the owner of the planted long-term key).
type CloudIdentity struct {
	Type   string `json:"type"` // user | assumed-role
	Name   string `json:"name"`
	UserID string `json:"user_id"` // AIDA.../AROA... aws:userid
}

// CloudInstance is the EC2 instance IMDS and DescribeInstances report.
type CloudInstance struct {
	ID         string            `json:"id"`   // i-...
	Type       string            `json:"type"` // e.g. p4d.24xlarge
	Role       string            `json:"role"` // instance-profile role name
	AZ         string            `json:"az"`
	PrivateIP  string            `json:"private_ip"`
	PublicIP   string            `json:"public_ip,omitempty"`
	ImageID    string            `json:"image_id"` // ami-...
	VPC        string            `json:"vpc,omitempty"`
	Subnet     string            `json:"subnet,omitempty"`
	SG         string            `json:"security_group,omitempty"`
	LaunchedAt string            `json:"launched_at,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
}

// CloudUser is an IAM user. AccessKeyID, if set, is the AKIA id listed by
// ListAccessKeys; the secret is never stored.
type CloudUser struct {
	Name        string   `json:"name"`
	ID          string   `json:"id"`  // AIDA...
	Arn         string   `json:"arn"` // computed when empty
	CreatedAt   string   `json:"created_at"`
	AccessKeyID string   `json:"access_key_id,omitempty"`
	Policies    []string `json:"policies,omitempty"`
}

// CloudRole is an IAM role.
type CloudRole struct {
	Name          string   `json:"name"`
	ID            string   `json:"id"` // AROA...
	Arn           string   `json:"arn"`
	CreatedAt     string   `json:"created_at"`
	TrustedEntity string   `json:"trusted_entity,omitempty"`
	Policies      []string `json:"policies,omitempty"`
}

// CloudBucket is an S3 bucket and its objects.
type CloudBucket struct {
	Name      string        `json:"name"`
	CreatedAt string        `json:"created_at"`
	Region    string        `json:"region,omitempty"`
	Objects   []CloudObject `json:"objects,omitempty"`
}

// CloudObject is one S3 object. Body may contain {{canary:<slot>}}.
type CloudObject struct {
	Key          string `json:"key"`
	Body         string `json:"body"`
	ContentType  string `json:"content_type,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
	StorageClass string `json:"storage_class,omitempty"`
}

// CloudSecret is a Secrets Manager secret. Value may contain {{canary:<slot>}}.
type CloudSecret struct {
	Name        string `json:"name"`
	Arn         string `json:"arn"`
	Description string `json:"description,omitempty"`
	Value       string `json:"value"`
	CreatedAt   string `json:"created_at,omitempty"`
	RotatedAt   string `json:"rotated_at,omitempty"`
}

// CloudParameter is an SSM Parameter Store entry. A SecureString value may
// contain {{canary:<slot>}}.
type CloudParameter struct {
	Name  string `json:"name"`
	Type  string `json:"type"` // String | StringList | SecureString
	Value string `json:"value"`
}

// CloudCluster is an EKS or ECS cluster returned by discovery.
type CloudCluster struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`               // eks | ecs
	Arn      string `json:"arn"`                // computed when empty
	Endpoint string `json:"endpoint,omitempty"` // EKS API server URL
	Version  string `json:"version,omitempty"`
	Status   string `json:"status,omitempty"`
}

// CloudTrailEvent is one synthetic CloudTrail record for LookupEvents.
type CloudTrailEvent struct {
	Time      string `json:"time"`
	Name      string `json:"name"`     // eventName, e.g. GetSecretValue
	Source    string `json:"source"`   // eventSource, e.g. secretsmanager.amazonaws.com
	Username  string `json:"username"` // identity name
	Region    string `json:"region,omitempty"`
	SourceIP  string `json:"source_ip,omitempty"`
	Resources string `json:"resources,omitempty"`
}

// Kube is the persona's synthetic Kubernetes API server, reached at
// k8s.<domain> by a client a planted ~/.kube/config points there. It answers a
// read-only subset of the API (discovery, namespaces, pods, deployments,
// secrets, configmaps, service accounts, nodes, SelfSubjectAccessReview) from
// this content. Secret and configmap values may contain {{canary:<slot>}},
// minted per read and base64-encoded into the response, so a value pulled from
// the cluster and reused elsewhere correlates across protocols.
type Kube struct {
	Version    string `json:"version"`     // e.g. v1.30.3
	GitVersion string `json:"git_version"` // e.g. v1.30.3-eks-...
	Platform   string `json:"platform"`    // e.g. linux/amd64
	// TokenSlot is the canary slot for the service-account bearer token planted
	// in ~/.kube/config. A use of it in an Authorization header names the read.
	TokenSlot  string          `json:"token_slot"`
	Namespaces []KubeNamespace `json:"namespaces,omitempty"`
	Nodes      []KubeNode      `json:"nodes,omitempty"`
}

// KubeNamespace is a namespace and the objects in it.
type KubeNamespace struct {
	Name            string           `json:"name"`
	Pods            []KubePod        `json:"pods,omitempty"`
	Deployments     []KubeDeployment `json:"deployments,omitempty"`
	Secrets         []KubeSecret     `json:"secrets,omitempty"`
	ConfigMaps      []KubeConfigMap  `json:"configmaps,omitempty"`
	ServiceAccounts []string         `json:"service_accounts,omitempty"`
}

// KubePod is a running pod.
type KubePod struct {
	Name   string `json:"name"`
	Image  string `json:"image"`
	Status string `json:"status"` // e.g. Running
	Node   string `json:"node"`
	PodIP  string `json:"pod_ip,omitempty"`
	SA     string `json:"service_account,omitempty"`
}

// KubeDeployment is a deployment.
type KubeDeployment struct {
	Name     string `json:"name"`
	Replicas int    `json:"replicas"`
	Image    string `json:"image"`
}

// KubeSecret is a Secret. Data values are plaintext here (they may contain
// {{canary:<slot>}}); the adapter base64-encodes them into the response.
type KubeSecret struct {
	Name string            `json:"name"`
	Type string            `json:"type"` // e.g. Opaque, kubernetes.io/dockerconfigjson
	Data map[string]string `json:"data"`
}

// KubeConfigMap is a ConfigMap (plaintext data).
type KubeConfigMap struct {
	Name string            `json:"name"`
	Data map[string]string `json:"data"`
}

// KubeNode is a cluster node; GPU nodes advertise nvidia.com/gpu capacity.
type KubeNode struct {
	Name           string `json:"name"`
	InstanceType   string `json:"instance_type"`
	KubeletVersion string `json:"kubelet_version"`
	InternalIP     string `json:"internal_ip"`
	GPU            int    `json:"gpu,omitempty"`
	ProviderID     string `json:"provider_id,omitempty"`
}

// Memory is the customer team's shared agent memory, exposed through the MCP
// memory_* tools. A leaked team key reads all of it, so an actor can discover
// other principals' notes; some notes are canary memories whose content holds a
// {{canary:<slot>}} (a credential planted where an agent stores context), minted
// per read. Writes and shares are not persisted; they are recorded as intent
// (memory poisoning, propagation).
type Memory struct {
	Notes []MemoryNote `json:"notes,omitempty"`
}

// MemoryNote is one stored memory owned by a principal (a person or an agent).
type MemoryNote struct {
	ID      string   `json:"id"`
	Owner   string   `json:"owner"` // principal that wrote it
	Kind    string   `json:"kind"`  // note | runbook | credential | preference
	Title   string   `json:"title"`
	Content string   `json:"content"` // may contain {{canary:<slot>}}
	Tags    []string `json:"tags,omitempty"`
	Created string   `json:"created"`
	Shared  []string `json:"shared,omitempty"` // principals it is shared with
}

// RAG is the persona's retrieval knowledge base and vector store, exposed
// through the MCP kb_* tools. Documents are grouped into collections (an
// engineering wiki, runbooks, a chat export, support tickets); some are canary
// documents whose content holds a {{canary:<slot>}}, minted per retrieval. Each
// document carries a Taint id recorded on retrieval, so a later use of its
// content correlates the retrieval with the movement (information lineage).
type RAG struct {
	Docs []RAGDoc `json:"docs,omitempty"`
}

// RAGDoc is one retrievable document.
type RAGDoc struct {
	ID         string   `json:"id"`
	Collection string   `json:"collection"`
	Title      string   `json:"title"`
	Source     string   `json:"source"`  // where it came from (url, path, channel)
	Content    string   `json:"content"` // may contain {{canary:<slot>}}
	Tags       []string `json:"tags,omitempty"`
	Updated    string   `json:"updated"`
	Taint      string   `json:"taint,omitempty"` // lineage id recorded on retrieval
}

// Lure is one wording of a honey description.
type Lure struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

// OAuth describes the persona's authorization server.
type OAuth struct {
	Scopes []Scope `json:"scopes"`
	// ClientSlot is the canary slot for secrets issued by dynamic client
	// registration, and TokenSlot the one for access tokens.
	ClientSlot string `json:"client_slot"`
	TokenSlot  string `json:"token_slot"`
}

// Scope is one OAuth scope. Honey scopes are plausible but no legitimate
// integration needs them: asking for one is a signal on its own.
type Scope struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Honey       bool   `json:"honey,omitempty"`
	// Grantable scopes can be issued to self-registered clients.
	Grantable bool `json:"grantable,omitempty"`
}

// CanarySpec describes the shape of one canary value. Values themselves are
// derived per spoke (see package canary) so a leak identifies its origin.
type CanarySpec struct {
	Slot   string `json:"slot"`
	Prefix string `json:"prefix"`
	Length int    `json:"length"`
}

// ChainStep is one stage of the behavioral canary chain.
type ChainStep struct {
	Stage int    `json:"stage"`
	Name  string `json:"name"`
	Kind  string `json:"kind"` // events.KindCanaryExposed or events.KindCanaryUsed
	Slot  string `json:"slot"`
	Score int    `json:"score"`
}

// Parse decodes and validates a pack.
func Parse(data []byte) (*Pack, error) {
	var p Pack
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("worldpack: %w", err)
	}
	if p.ID == "" || p.Version == "" || p.Company.Domain == "" {
		return nil, errors.New("worldpack: id, version and company.domain are required")
	}
	slots := map[string]bool{}
	for _, c := range p.Canaries {
		if c.Slot == "" || c.Length < 16 {
			return nil, fmt.Errorf("worldpack: canary %q needs a slot and length >= 16", c.Slot)
		}
		slots[c.Slot] = true
	}
	for _, k := range p.ProviderKeys {
		if !slots[k.Slot] {
			return nil, fmt.Errorf("worldpack: provider key %q references unknown slot %q", k.Name, k.Slot)
		}
	}
	for _, a := range p.ServiceAccounts {
		if !slots[a.Slot] {
			return nil, fmt.Errorf("worldpack: service account %q references unknown slot %q", a.Name, a.Slot)
		}
	}
	if p.SSH != nil {
		for _, u := range p.SSH.Users {
			if !slots[u.Slot] {
				return nil, fmt.Errorf("worldpack: ssh user %q references unknown slot %q", u.Name, u.Slot)
			}
		}
	}
	for _, slot := range []string{p.OAuth.ClientSlot, p.OAuth.TokenSlot} {
		if slot != "" && !slots[slot] {
			return nil, fmt.Errorf("worldpack: oauth references unknown slot %q", slot)
		}
	}
	for _, s := range p.Chain {
		if !slots[s.Slot] {
			return nil, fmt.Errorf("worldpack: chain stage %d references unknown slot %q", s.Stage, s.Slot)
		}
	}
	if p.Redis != nil {
		for key, val := range p.Redis.Keys {
			for _, m := range canaryRefRE.FindAllStringSubmatch(val, -1) {
				if !slots[m[1]] {
					return nil, fmt.Errorf("worldpack: redis key %q references unknown slot %q", key, m[1])
				}
			}
		}
	}
	if p.Postgres != nil {
		for _, u := range p.Postgres.Users {
			if !slots[u.Slot] {
				return nil, fmt.Errorf("worldpack: postgres user %q references unknown slot %q", u.Name, u.Slot)
			}
		}
		for _, q := range p.Postgres.Queries {
			for _, row := range q.Rows {
				for _, cell := range row {
					for _, m := range canaryRefRE.FindAllStringSubmatch(cell, -1) {
						if !slots[m[1]] {
							return nil, fmt.Errorf("worldpack: postgres query %q references unknown slot %q", q.Match, m[1])
						}
					}
				}
			}
		}
	}
	if p.Cloud != nil {
		for _, slot := range []string{p.Cloud.AccessKeySlot, p.Cloud.STSKeySlot} {
			if slot != "" && !slots[slot] {
				return nil, fmt.Errorf("worldpack: cloud references unknown slot %q", slot)
			}
		}
		refs := map[string]string{}
		for _, b := range p.Cloud.Buckets {
			for _, o := range b.Objects {
				refs["s3 object "+b.Name+"/"+o.Key] = o.Body
			}
		}
		for _, sec := range p.Cloud.Secrets {
			refs["secret "+sec.Name] = sec.Value
		}
		for _, param := range p.Cloud.Parameters {
			refs["parameter "+param.Name] = param.Value
		}
		for where, val := range refs {
			for _, m := range canaryRefRE.FindAllStringSubmatch(val, -1) {
				if !slots[m[1]] {
					return nil, fmt.Errorf("worldpack: cloud %s references unknown slot %q", where, m[1])
				}
			}
		}
	}
	if p.Kube != nil {
		if p.Kube.TokenSlot != "" && !slots[p.Kube.TokenSlot] {
			return nil, fmt.Errorf("worldpack: kube references unknown token slot %q", p.Kube.TokenSlot)
		}
		for _, ns := range p.Kube.Namespaces {
			for _, sec := range ns.Secrets {
				for key, val := range sec.Data {
					for _, m := range canaryRefRE.FindAllStringSubmatch(val, -1) {
						if !slots[m[1]] {
							return nil, fmt.Errorf("worldpack: kube secret %s/%s[%s] references unknown slot %q", ns.Name, sec.Name, key, m[1])
						}
					}
				}
			}
		}
	}
	if p.Memory != nil {
		for _, n := range p.Memory.Notes {
			for _, m := range canaryRefRE.FindAllStringSubmatch(n.Content, -1) {
				if !slots[m[1]] {
					return nil, fmt.Errorf("worldpack: memory note %q references unknown slot %q", n.ID, m[1])
				}
			}
		}
	}
	if p.RAG != nil {
		for _, doc := range p.RAG.Docs {
			for _, m := range canaryRefRE.FindAllStringSubmatch(doc.Content, -1) {
				if !slots[m[1]] {
					return nil, fmt.Errorf("worldpack: rag doc %q references unknown slot %q", doc.ID, m[1])
				}
			}
		}
	}
	return &p, nil
}

// canaryRefRE matches {{canary:<slot>}} placeholders in world-pack values.
var canaryRefRE = regexp.MustCompile(`\{\{canary:([a-z0-9_]+)\}\}`)

// Envelope is a signed pack as distributed by the hub.
type Envelope struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

// Sign wraps raw pack JSON in a signed envelope.
func Sign(key ed25519.PrivateKey, raw []byte) Envelope {
	return Envelope{Payload: raw, Signature: ed25519.Sign(key, raw)}
}

// Open verifies an envelope and returns the parsed pack.
func Open(pub ed25519.PublicKey, env Envelope) (*Pack, error) {
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, env.Payload, env.Signature) {
		return nil, errors.New("worldpack: signature verification failed")
	}
	return Parse(env.Payload)
}
