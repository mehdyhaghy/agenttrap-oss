package demogpu

// S3 on the aws.<domain> endpoint, path-style (the planted ~/.aws/config sets
// addressing_style = path so the SDK does not prepend the bucket to the host).
// Listing is open discovery; GetObject bodies are the value traps and may carry
// {{canary:<slot>}} minted per read. A PutObject is recorded as a possible
// exfiltration sink and accepted.

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"

	"agenttrap/internal/worldpack"
)

const s3NS = "http://s3.amazonaws.com/doc/2006-03-01/"

func (s *Server) awsS3(w http.ResponseWriter, r *http.Request, auth awsAuth, reqID string) {
	bucket, key := s3Path(r.URL.Path)
	// The buckets are private: an unsigned request is refused the way S3
	// refuses anonymous access, not as a web server.
	if auth.accessKeyID == "" {
		s3Error(w, reqID, http.StatusForbidden, "AccessDenied", "Access Denied", "", "")
		return
	}
	switch {
	case bucket == "":
		s.s3ListBuckets(w, r, reqID)
	case key == "" && r.Method == http.MethodHead:
		s.s3HeadBucket(w, r, reqID, bucket)
	case key == "":
		s.s3ListObjects(w, r, reqID, bucket)
	case r.Method == http.MethodPut:
		s.s3PutObject(w, r, reqID, bucket, key)
	case r.Method == http.MethodHead:
		s.s3GetObject(w, r, reqID, bucket, key, true)
	default:
		s.s3GetObject(w, r, reqID, bucket, key, false)
	}
}

// s3Path splits a path-style URL into bucket and object key.
func s3Path(p string) (bucket, key string) {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return "", ""
	}
	bucket, key, _ = strings.Cut(p, "/")
	return bucket, key
}

// findBucketRaw returns the pack bucket by name, or nil.
func (s *Server) findBucketRaw(name string) *worldpack.CloudBucket {
	for i := range s.pack.Cloud.Buckets {
		if s.pack.Cloud.Buckets[i].Name == name {
			return &s.pack.Cloud.Buckets[i]
		}
	}
	return nil
}

func (s *Server) s3ListBuckets(w http.ResponseWriter, r *http.Request, reqID string) {
	s.noteCloud(r, "s3", "ListBuckets", nil)
	c := s.pack.Cloud
	type bucket struct {
		Name    string `xml:"Name"`
		Created string `xml:"CreationDate"`
	}
	var buckets []bucket
	for _, b := range c.Buckets {
		buckets = append(buckets, bucket{Name: b.Name, Created: defaultStr(b.CreatedAt, awsNow())})
	}
	type result struct {
		XMLName     xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListAllMyBucketsResult"`
		OwnerID     string   `xml:"Owner>ID"`
		DisplayName string   `xml:"Owner>DisplayName"`
		Buckets     []bucket `xml:"Buckets>Bucket"`
	}
	writeS3XML(w, reqID, http.StatusOK, result{OwnerID: s3OwnerID(c.Account),
		DisplayName: defaultStr(c.Identity.Name, "demogpu"), Buckets: buckets})
}

func (s *Server) s3HeadBucket(w http.ResponseWriter, r *http.Request, reqID, bucket string) {
	s.noteCloud(r, "s3", "HeadBucket", map[string]any{"bucket": truncate(bucket, 200)})
	if s.findBucketRaw(bucket) == nil {
		s3headers(w, reqID)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("x-amz-bucket-region", defaultStr(s.awsRegion(), "us-east-1"))
	s3headers(w, reqID)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) s3ListObjects(w http.ResponseWriter, r *http.Request, reqID, bucket string) {
	prefix := r.URL.Query().Get("prefix")
	s.noteCloud(r, "s3", "ListObjects", map[string]any{"bucket": truncate(bucket, 200), "prefix": truncate(prefix, 200)})
	b := s.findBucketRaw(bucket)
	if b == nil {
		s3Error(w, reqID, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist", bucket, "")
		return
	}
	v2 := r.URL.Query().Get("list-type") == "2"
	type object struct {
		Key          string `xml:"Key"`
		LastModified string `xml:"LastModified"`
		ETag         string `xml:"ETag"`
		Size         int    `xml:"Size"`
		StorageClass string `xml:"StorageClass"`
	}
	var contents []object
	for _, o := range b.Objects {
		if prefix != "" && !strings.HasPrefix(o.Key, prefix) {
			continue
		}
		// List the object's on-disk size, so the count matches a later GET; the
		// literal placeholder length is close enough and never a real secret.
		contents = append(contents, object{Key: o.Key, LastModified: defaultStr(o.LastModified, awsNow()),
			ETag: etag(o.Body), Size: len(o.Body), StorageClass: defaultStr(o.StorageClass, "STANDARD")})
	}
	type result struct {
		XMLName     xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult"`
		Name        string   `xml:"Name"`
		Prefix      string   `xml:"Prefix"`
		KeyCount    int      `xml:"KeyCount,omitempty"`
		MaxKeys     int      `xml:"MaxKeys"`
		IsTruncated bool     `xml:"IsTruncated"`
		Marker      string   `xml:"Marker,omitempty"`
		Contents    []object `xml:"Contents"`
	}
	res := result{Name: bucket, Prefix: prefix, MaxKeys: 1000, Contents: contents}
	if v2 { // KeyCount is a ListObjectsV2 element only
		res.KeyCount = len(contents)
	}
	writeS3XML(w, reqID, http.StatusOK, res)
}

func (s *Server) s3GetObject(w http.ResponseWriter, r *http.Request, reqID, bucket, key string, head bool) {
	op := "GetObject"
	if head {
		op = "HeadObject"
	}
	s.noteCloud(r, "s3", op, map[string]any{"bucket": truncate(bucket, 200), "key": truncate(key, 500)})
	b := s.findBucketRaw(bucket)
	if b == nil {
		s3Error(w, reqID, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist", bucket, "")
		return
	}
	for _, o := range b.Objects {
		if o.Key != key {
			continue
		}
		body := s.renderCanaries(r, o.Body, "s3", map[string]any{"bucket": bucket, "key": key})
		ct := defaultStr(o.ContentType, "application/octet-stream")
		w.Header().Set("Content-Type", ct)
		w.Header().Set("ETag", etag(o.Body))
		w.Header().Set("Last-Modified", parseOrNow(o.LastModified).Format(http.TimeFormat))
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		s3headers(w, reqID)
		w.WriteHeader(http.StatusOK)
		if !head {
			_, _ = w.Write([]byte(body))
		}
		return
	}
	s3Error(w, reqID, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.", bucket, key)
}

func (s *Server) s3PutObject(w http.ResponseWriter, r *http.Request, reqID, bucket, key string) {
	// The captured request body (server.go captureBody) records what was
	// uploaded; a canary in it means data taken from us is being written back.
	s.noteCloud(r, "s3", "PutObject", map[string]any{"bucket": truncate(bucket, 200), "key": truncate(key, 500)})
	w.Header().Set("ETag", `"`+strings.Repeat("0", 32)+`"`)
	s3headers(w, reqID)
	w.WriteHeader(http.StatusOK)
}

// --- helpers ---

func writeS3XML(w http.ResponseWriter, reqID string, status int, v any) {
	w.Header().Set("Content-Type", "application/xml")
	s3headers(w, reqID)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(v)
}

func s3headers(w http.ResponseWriter, reqID string) {
	w.Header().Set("Server", "AmazonS3")
	w.Header().Set("x-amz-request-id", strings.ToUpper(strings.ReplaceAll(reqID, "-", ""))[:16])
	w.Header().Set("x-amz-id-2", base64Pad(reqID))
}

func s3Error(w http.ResponseWriter, reqID string, status int, code, msg, bucket, key string) {
	type errBody struct {
		XMLName    xml.Name `xml:"Error"`
		Code       string   `xml:"Code"`
		Message    string   `xml:"Message"`
		BucketName string   `xml:"BucketName,omitempty"`
		Key        string   `xml:"Key,omitempty"`
		RequestID  string   `xml:"RequestId"`
		HostID     string   `xml:"HostId"`
	}
	w.Header().Set("Content-Type", "application/xml")
	s3headers(w, reqID)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(errBody{Code: code, Message: msg, BucketName: bucket, Key: key,
		RequestID: strings.ToUpper(strings.ReplaceAll(reqID, "-", ""))[:16], HostID: base64Pad(reqID)})
}

func s3OwnerID(account string) string {
	sum := md5.Sum([]byte("owner:" + account))
	return hex.EncodeToString(sum[:])
}

func etag(body string) string {
	sum := md5.Sum([]byte(body))
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

func base64Pad(reqID string) string {
	sum := md5.Sum([]byte("hostid:" + reqID))
	return hex.EncodeToString(sum[:]) + "=="
}

func parseOrNow(v string) time.Time {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t
	}
	if t, err := time.Parse("2006-01-02T15:04:05Z", v); err == nil {
		return t
	}
	return time.Now().UTC()
}
