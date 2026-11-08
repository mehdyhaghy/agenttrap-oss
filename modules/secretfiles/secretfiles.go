// Package secretfiles answers the most common scanner request of all: leaked
// configuration and credential files (.env and its variants, .git metadata,
// AWS credentials, compose files, CI configs, wp-config backups). Each file
// is believable for the host it is served on and carries per-exposure
// canaries from the persona, so a key later used anywhere names the exact
// download it came from. Files only ever reveal the canaries they contain.
package secretfiles

import (
	"fmt"
	"hash/fnv"
	"io"
	"math/rand/v2"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"

	"agenttrap/modules"
)

// Module is the secret-file trap.
type Module struct{}

// New returns the module.
func New() *Module { return &Module{} }

// Name implements modules.Module.
func (*Module) Name() string { return "secretfiles" }

// Families of files served, by signal name.
const (
	famEnv            = "env_file"
	famGitConfig      = "git_config"
	famGitHead        = "git_head"
	famGitLog         = "git_log"
	famGitCredentials = "git_credentials"
	famAWSCredentials = "aws_credentials"
	famAWSConfig      = "aws_config"
	famCompose        = "docker_compose"
	famDockerfile     = "dockerfile"
	famCredentials    = "credentials_json"
	famSecrets        = "secrets_json"
	famConfigJSON     = "config_json"
	famConfigJS       = "config_js"
	famNpmrc          = "npmrc"
	famGitlabCI       = "gitlab_ci"
	famWorkflow       = "github_workflow"
	famWPConfig       = "wp_config_backup"
)

var (
	envName      = regexp.MustCompile(`^\.env(\.(local|production|development|bak|backup|save|old|prod|staging|example|dev|test|live|docker))?$`)
	wpBackupName = regexp.MustCompile(`^wp-config\.php(\.(bak|old|save|orig|swp|txt)|~)$`)
	workflowPath = regexp.MustCompile(`/\.github/workflows/[^/]+\.ya?ml$`)
)

// normalize lowercases a path and strips the junk scanners prepend to dodge
// naive filters: NUL bytes, spaces, doubled slashes.
func normalize(p string) string {
	p = strings.Map(func(r rune) rune {
		if r == 0 || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, strings.ToLower(p))
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	return p
}

// family names the secret file a path asks for, or "".
func family(rawPath string) string {
	p := normalize(rawPath)
	// Traversal, Vite /@fs/ reads and AI configs belong to other modules.
	if strings.Contains(p, "..") || strings.Contains(p, "%2e") || strings.Contains(p, "/@fs/") || strings.Contains(p, "litellm") {
		return ""
	}
	base := path.Base(p)
	switch {
	case envName.MatchString(base):
		return famEnv
	case strings.HasSuffix(p, "/.git/config"):
		return famGitConfig
	case strings.HasSuffix(p, "/.git/head"):
		return famGitHead
	case strings.HasSuffix(p, "/.git/logs/head"):
		return famGitLog
	case base == ".git-credentials":
		return famGitCredentials
	case strings.HasSuffix(p, "/.aws/credentials"):
		return famAWSCredentials
	case strings.HasSuffix(p, "/.aws/config"):
		return famAWSConfig
	case base == "docker-compose.yml" || base == "docker-compose.yaml":
		return famCompose
	case base == "dockerfile":
		return famDockerfile
	case base == "credentials.json":
		return famCredentials
	case base == "secrets.json":
		return famSecrets
	case base == "config.json":
		return famConfigJSON
	case base == "config.js":
		return famConfigJS
	case base == ".npmrc":
		return famNpmrc
	case base == ".gitlab-ci.yml":
		return famGitlabCI
	case workflowPath.MatchString(p):
		return famWorkflow
	case wpBackupName.MatchString(base):
		return famWPConfig
	}
	return ""
}

// Claim takes requests for known secret files on web-facing hosts.
func (*Module) Claim(r modules.Request) modules.Claim {
	if modules.WebSurface(r.Surface) && family(r.URL.Path) != "" {
		return modules.Attack
	}
	return modules.Pass
}

// Serve implements modules.Module.
func (*Module) Serve(w http.ResponseWriter, r modules.Request) modules.Hit {
	fam := family(r.URL.Path)
	hit := modules.Hit{Attack: "Secret file exposure", Stage: modules.StageProbe, Signals: []string{fam},
		Detail: map[string]any{"file": fam}}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	default:
		_, _ = modules.ReadBody(r.Request, 0)
		notAllowed(w)
		return hit
	}
	if r.Method == http.MethodHead {
		r.Reveal = nil // nothing is shown, so nothing is exposed
	}
	s := newSecrets(r)
	body := render(fam, s)
	if len(s.slots) > 0 {
		hit.Detail["slots"] = s.slots
	}
	w.Header().Set("Content-Type", contentType(r.URL.Path, fam))
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Last-Modified", lastModified)
	w.Header().Set("ETag", fmt.Sprintf(`"%x-%x"`, lastModifiedUnix, len(body)))
	w.Header().Set("Accept-Ranges", "bytes")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = io.WriteString(w, body)
	}
	return hit
}

const (
	lastModified     = "Tue, 14 Jan 2025 09:12:44 GMT"
	lastModifiedUnix = 1736845964
)

// contentType is what nginx's stock mime.types (default_type
// application/octet-stream) sends for the file.
func contentType(p, fam string) string {
	switch {
	case fam == famConfigJSON || fam == famCredentials || fam == famSecrets:
		return "application/json"
	case fam == famConfigJS:
		return "application/javascript"
	case strings.HasSuffix(strings.ToLower(p), ".txt"):
		return "text/plain"
	}
	return "application/octet-stream"
}

func notAllowed(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusMethodNotAllowed)
	_, _ = io.WriteString(w, "<html>\r\n<head><title>405 Not Allowed</title></head>\r\n<body>\r\n<center><h1>405 Not Allowed</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n")
}

// secrets hands out values for one response: persona canaries when the
// facade provides them (each recorded as exposed), otherwise realistic
// stand-ins that stay the same for the same path.
type secrets struct {
	r     modules.Request
	rnd   *rand.Rand
	cache map[string]string
	slots []string
	// flavor
	persona   bool
	app       string
	domain    string
	repo      string
	dbHost    string
	redisHost string
	bucket    string
}

func newSecrets(r modules.Request) *secrets {
	h := fnv.New64a()
	_, _ = io.WriteString(h, r.Host+"|"+r.URL.Path)
	seed := h.Sum64()
	s := &secrets{r: r, rnd: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)), cache: map[string]string{}}
	if r.Surface != "" {
		s.persona = true
		s.app, s.domain, s.repo = "demogpu-platform", "demogpu.example", "github.com/demogpu/platform.git"
		s.dbHost, s.redisHost, s.bucket = "pg-primary.internal.demogpu.example", "cache-01.internal.demogpu.example", "demogpu-model-artifacts"
	} else {
		s.app, s.domain, s.repo = "ops-portal", "ops.corp.local", "git.corp.local/infra/ops-portal.git"
		s.dbHost, s.redisHost, s.bucket = "10.0.3.12", "10.0.3.14", "ops-portal-backups"
	}
	return s
}

const (
	alnum   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b32     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	b64     = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
	letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

func (s *secrets) rand(alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[s.rnd.IntN(len(alphabet))]
	}
	return string(b)
}

// fallbacks are stand-ins shaped like each persona slot's canaries.
func (s *secrets) fallback(slot string) string {
	switch slot {
	case "provider_key_vllm":
		return "sk-demo-" + s.rand(alnum, 40)
	case "docs_sample_key":
		return "dgp_test_" + s.rand(alnum, 32)
	case "aws_access_key_id":
		return "AKIA" + s.rand(b32, 16)
	case "pg_app_password":
		return "pg_" + s.rand(alnum, 24)
	case "redis_session_token":
		return "glt-" + s.rand(alnum, 32)
	case "hf_token":
		return "hf_" + s.rand(letters, 34)
	case "ssh_deploy_password":
		return "vllm-deploy-" + s.rand(alnum, 12)
	}
	return s.rand(alnum, 32)
}

// get returns the value for slot, revealing a canary at most once per
// response and remembering which slots were exposed.
func (s *secrets) get(slot string) string {
	if v, ok := s.cache[slot]; ok {
		return v
	}
	v := ""
	if s.r.Reveal != nil {
		v = s.r.Reveal(slot)
	}
	if v != "" {
		s.slots = append(s.slots, slot)
	} else {
		v = s.fallback(slot)
	}
	s.cache[slot] = v
	return v
}

// local is a per-response value with no canary behind it (salts, app keys).
func (s *secrets) local(name, alphabet string, n int) string {
	key := "local:" + name
	if v, ok := s.cache[key]; ok {
		return v
	}
	v := s.rand(alphabet, n)
	s.cache[key] = v
	return v
}

func (s *secrets) awsSecret() string { return s.local("aws_secret", b64, 40) }
