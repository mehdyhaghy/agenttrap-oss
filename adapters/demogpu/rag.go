package demogpu

// The retrieval knowledge base and vector store, exposed through the MCP kb_*
// tools (kb_collections/kb_search/kb_get/kb_similar). Documents are grouped
// into collections (an engineering wiki, runbooks, a chat export, support
// tickets); some are canary documents whose content holds a planted credential,
// minted on retrieval. Each document carries a taint id recorded on the
// retrieval event, so a later use of its content correlates back (lineage).
// Reuses maskSecrets/hasCanary/credentialQuery/snippet from memory.go.

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	"agenttrap/internal/worldpack"
)

func (s *Server) ragTool(r *http.Request, acc access, name string, args map[string]any, detail map[string]any) map[string]any {
	if s.pack.RAG == nil {
		return toolText("The knowledge base is not enabled for this team.", true)
	}
	detail["op"] = name
	switch name {
	case "kb_collections":
		counts := map[string]int{}
		var order []string
		for _, d := range s.pack.RAG.Docs {
			if counts[d.Collection] == 0 {
				order = append(order, d.Collection)
			}
			counts[d.Collection]++
		}
		var b strings.Builder
		for _, c := range order {
			fmt.Fprintf(&b, "%s (%d document(s))\n", c, counts[c])
		}
		return toolText(b.String(), false)
	case "kb_search":
		q, _ := args["query"].(string)
		coll, _ := args["collection"].(string)
		detail["query"] = truncate(q, 200)
		if coll != "" {
			detail["collection"] = truncate(coll, 80)
		}
		if credentialQuery(q) {
			detail["credential_search"] = true
		}
		var b strings.Builder
		hits := 0
		for _, d := range s.pack.RAG.Docs {
			if coll != "" && !strings.EqualFold(d.Collection, coll) {
				continue
			}
			if q == "" || ragMatch(d, q) {
				fmt.Fprintf(&b, "%s  [%s]  %s — %s\n    %s\n", d.ID, d.Collection, d.Title, d.Source, snippet(d.Content))
				if hits++; hits >= 8 {
					break
				}
			}
		}
		detail["hits"] = hits
		if hits == 0 {
			return toolText("No documents matched.", false)
		}
		return toolText(b.String(), false)
	case "kb_get":
		id, _ := args["id"].(string)
		detail["doc_id"] = truncate(id, 80)
		for _, d := range s.pack.RAG.Docs {
			if strings.EqualFold(d.ID, id) {
				detail["collection"] = d.Collection
				detail["source"] = truncate(d.Source, 200)
				if d.Taint != "" {
					detail["taint"] = d.Taint
				}
				if hasCanary(d.Content) {
					detail["has_secret"] = true
				}
				content := s.renderCanaries(r, d.Content, "rag", map[string]any{"doc_id": d.ID, "collection": d.Collection, "taint": d.Taint})
				header := fmt.Sprintf("id: %s\ncollection: %s\ntitle: %s\nsource: %s\nupdated: %s\n\n", d.ID, d.Collection, d.Title, d.Source, d.Updated)
				return toolText(header+content, false)
			}
		}
		return toolText("No document with id "+truncate(id, 80), true)
	case "kb_similar":
		id, _ := args["id"].(string)
		detail["doc_id"] = truncate(id, 80)
		var target *worldpack.RAGDoc
		for i := range s.pack.RAG.Docs {
			if strings.EqualFold(s.pack.RAG.Docs[i].ID, id) {
				target = &s.pack.RAG.Docs[i]
				break
			}
		}
		if target == nil {
			return toolText("No document with id "+truncate(id, 80), true)
		}
		var b strings.Builder
		n := 0
		for _, d := range s.pack.RAG.Docs {
			if d.ID == target.ID {
				continue
			}
			if ragSimilar(*target, d) {
				fmt.Fprintf(&b, "%s  [%s]  %s — %s\n", d.ID, d.Collection, d.Title, d.Source)
				if n++; n >= 6 {
					break
				}
			}
		}
		if n == 0 {
			return toolText("No similar documents.", false)
		}
		return toolText(b.String(), false)
	}
	return toolText("Unknown knowledge-base tool: "+truncate(name, 80), true)
}

func ragMatch(d worldpack.RAGDoc, q string) bool {
	q = strings.ToLower(q)
	if strings.Contains(strings.ToLower(d.Title), q) || strings.Contains(strings.ToLower(maskSecrets(d.Content)), q) ||
		strings.Contains(strings.ToLower(d.Source), q) {
		return true
	}
	for _, t := range d.Tags {
		if strings.Contains(strings.ToLower(t), q) {
			return true
		}
	}
	return false
}

// ragSimilar is a deterministic stand-in for vector similarity: same collection
// or a shared tag.
func ragSimilar(a, b worldpack.RAGDoc) bool {
	if a.Collection == b.Collection {
		return true
	}
	for _, t := range a.Tags {
		if slices.Contains(b.Tags, t) {
			return true
		}
	}
	return false
}
