package mcpserver

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	content "github.com/nullsub/mcp-uapi"
)

const (
	mimeMarkdown   = "text/markdown"
	mimeJSON       = "application/json"
	mimeJavaScript = "application/javascript"
)

type embeddedResource struct {
	URI         string
	Name        string
	Path        string
	Description string
	MIMEType    string
}

type documentAsset struct {
	Path        string
	URI         string
	Name        string
	Description string
	Aliases     []string
}

func agentGuideMarkdown() string {
	return mustEmbeddedText("docs/AGENT_GUIDE.md")
}

func apiReferenceMarkdown() string {
	return mustEmbeddedText("docs/API.md")
}

func scriptingAPIMarkdown() string {
	return mustEmbeddedText("docs/SCRIPTING.md")
}

func documentAssets() []documentAsset {
	return []documentAsset{
		{
			Path:        "docs/AGENT_GUIDE.md",
			URI:         "uapi://agent-guide",
			Name:        "Linux UAPI agent guide",
			Description: "Curated bootstrap guide for agents: resource reading, eval shape, runtime globals, reusable examples, and common workflow patterns.",
			Aliases:     []string{"uapi://docs/AGENT_GUIDE.md"},
		},
		{
			Path:        "docs/API.md",
			URI:         "uapi://api-reference",
			Name:        "Linux UAPI API reference",
			Description: "Eval scripting reference and workflow notes for Linux user-mode API exploration.",
			Aliases:     []string{"uapi://docs/API.md"},
		},
		{
			Path:        "docs/SCRIPTING.md",
			URI:         "uapi://scripting-api",
			Name:        "Linux UAPI scripting API",
			Description: "JavaScript eval API reference, runtime globals, wrappers, and examples.",
			Aliases:     []string{"uapi://docs/SCRIPTING.md"},
		},
		{
			Path:        "docs/EXAMPLES.md",
			URI:         "uapi://examples-guide",
			Name:        "Linux UAPI example guide",
			Description: "Narrative examples for composing eval workflows with sys, os, and io.",
			Aliases:     []string{"uapi://docs/EXAMPLES.md"},
		},
		{
			Path:        "docs/SECURITY.md",
			URI:         "uapi://security",
			Name:        "Linux UAPI security notes",
			Description: "Safety model, deployment guidance, and trust boundaries for MCP-UAPI.",
			Aliases:     []string{"uapi://docs/SECURITY.md"},
		},
	}
}

func documentResources() []embeddedResource {
	resources := make([]embeddedResource, 0, len(documentAssets())*2)
	for _, doc := range documentAssets() {
		resources = append(resources, embeddedResource{
			URI:         doc.URI,
			Name:        doc.Name,
			Path:        doc.Path,
			Description: doc.Description,
			MIMEType:    mimeMarkdown,
		})
		for _, alias := range doc.Aliases {
			resources = append(resources, embeddedResource{
				URI:         alias,
				Name:        doc.Name,
				Path:        doc.Path,
				Description: doc.Description,
				MIMEType:    mimeMarkdown,
			})
		}
	}
	return resources
}

func exampleScriptResources() []embeddedResource {
	examples := exampleScripts()
	resources := make([]embeddedResource, 0, len(examples))
	for _, example := range examples {
		resources = append(resources, embeddedResource{
			URI:         example.URI,
			Name:        example.Title,
			Path:        example.SourcePath,
			Description: example.Description,
			MIMEType:    mimeJavaScript,
		})
	}
	return resources
}

func exampleScripts() []ScriptingExample {
	matches, err := fs.Glob(content.Content, "examples/*.js")
	if err != nil {
		panic(fmt.Sprintf("glob embedded examples: %v", err))
	}
	sort.Strings(matches)

	examples := make([]ScriptingExample, 0, len(matches))
	for _, file := range matches {
		script := mustEmbeddedText(file)
		examples = append(examples, parseExampleScript(file, script))
	}
	return examples
}

func parseExampleScript(file, script string) ScriptingExample {
	name := defaultExampleName(file)
	example := ScriptingExample{
		Name:       name,
		Title:      titleFromName(name),
		URI:        "uapi://examples/" + path.Base(file),
		SourcePath: file,
		MIMEType:   mimeJavaScript,
		Script:     script,
	}

	for _, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(trimmed, "//") {
			break
		}
		key, value, ok := strings.Cut(strings.TrimSpace(strings.TrimPrefix(trimmed, "//")), ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "name":
			if value := strings.TrimSpace(value); value != "" {
				example.Name = value
			}
		case "title":
			if value := strings.TrimSpace(value); value != "" {
				example.Title = value
			}
		case "description":
			example.Description = strings.TrimSpace(value)
		case "tags":
			example.Tags = splitCSV(value)
		}
	}
	return example
}

func defaultExampleName(file string) string {
	base := strings.TrimSuffix(path.Base(file), path.Ext(file))
	trimmed := strings.TrimLeft(base, "0123456789")
	trimmed = strings.TrimLeft(trimmed, "-_.")
	if trimmed == "" {
		trimmed = base
	}
	return strings.ReplaceAll(trimmed, "-", "_")
}

func titleFromName(name string) string {
	parts := strings.Fields(strings.ReplaceAll(name, "_", " "))
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}

func splitCSV(value string) []string {
	fields := strings.Split(value, ",")
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field != "" {
			result = append(result, field)
		}
	}
	return result
}

func docsIndexMarkdown() string {
	var builder strings.Builder
	builder.WriteString("# MCP-UAPI Documentation\n\n")
	builder.WriteString("These files live in `docs/`, are embedded into the binary at build time, and are exposed as MCP resources.\n\n")
	for _, doc := range documentAssets() {
		fmt.Fprintf(&builder, "- `%s` - %s (`%s`)\n", doc.URI, doc.Name, doc.Path)
	}
	return builder.String()
}

func docsIndexJSON() string {
	return mustJSON(documentationResourceSummaries())
}

func examplesIndexMarkdown() string {
	var builder strings.Builder
	builder.WriteString("# MCP-UAPI Example Scripts\n\n")
	builder.WriteString("These scripts live in `examples/`, are embedded into the binary at build time, and are exposed as individual MCP resources. Read one and pass its text to the `eval` tool.\n\n")
	for _, example := range exampleScripts() {
		fmt.Fprintf(&builder, "- `%s` - %s", example.URI, example.Title)
		if example.Description != "" {
			fmt.Fprintf(&builder, ": %s", example.Description)
		}
		builder.WriteString("\n")
	}
	return builder.String()
}

func examplesIndexJSON() string {
	return mustJSON(exampleScriptSummaries())
}

func documentationResourceSummaries() []ResourceSummary {
	resources := documentResources()
	summaries := make([]ResourceSummary, 0, len(resources)+2)
	summaries = append(summaries,
		ResourceSummary{URI: "uapi://docs", Name: "MCP-UAPI documentation index", Description: "Human-readable index of embedded documentation resources.", MIMEType: mimeMarkdown},
		ResourceSummary{URI: "uapi://docs/index.json", Name: "MCP-UAPI documentation index JSON", Description: "Machine-readable index of embedded documentation resources.", MIMEType: mimeJSON},
	)
	for _, resource := range resources {
		summaries = append(summaries, ResourceSummary{URI: resource.URI, Name: resource.Name, Description: resource.Description, MIMEType: resource.MIMEType, SourcePath: resource.Path})
	}
	return summaries
}

func exampleScriptSummaries() []ScriptingExample {
	examples := exampleScripts()
	for i := range examples {
		examples[i].Script = ""
	}
	return examples
}

func resourceURIs() []string {
	resources := []string{"uapi://capabilities", "uapi://state"}
	for _, summary := range documentationResourceSummaries() {
		resources = append(resources, summary.URI)
	}
	resources = append(resources, "uapi://examples", "uapi://examples/index.json")
	for _, summary := range exampleScriptSummaries() {
		resources = append(resources, summary.URI)
	}
	sort.Strings(resources)
	return resources
}

func mustEmbeddedText(file string) string {
	data, err := content.Content.ReadFile(file)
	if err != nil {
		panic(fmt.Sprintf("read embedded %s: %v", file, err))
	}
	return string(data)
}

func mustJSON(value any) string {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("marshal resource index: %v", err))
	}
	return string(data)
}
