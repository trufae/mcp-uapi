package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

const (
	toolBundleSchema         = "mcp-uapi.tools.v1"
	maxManagedToolScriptSize = 1 << 20
	maxManagedToolMetaSize   = 64 << 10
	maxManagedToolTags       = 32
)

type managedTool struct {
	Name           string          `json:"name"`
	Description    string          `json:"description,omitempty"`
	Script         string          `json:"script"`
	InputSchema    json.RawMessage `json:"input_schema,omitempty"`
	Tags           []string        `json:"tags,omitempty"`
	ReadOnly       bool            `json:"read_only"`
	Destructive    bool            `json:"destructive"`
	TimeoutMS      uint32          `json:"timeout_ms,omitempty"`
	MaxLogEntries  uint32          `json:"max_log_entries,omitempty"`
	MaxResultBytes uint64          `json:"max_result_bytes,omitempty"`
	Metadata       map[string]any  `json:"metadata,omitempty"`
	Revision       uint64          `json:"revision"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

func (t *managedTool) UnmarshalJSON(data []byte) error {
	type managedToolAlias managedTool
	var decoded struct {
		managedToolAlias
		Destructive *bool `json:"destructive"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*t = managedTool(decoded.managedToolAlias)
	if decoded.Destructive == nil {
		t.Destructive = true
	} else {
		t.Destructive = *decoded.Destructive
	}
	return nil
}

type managedToolSummary struct {
	Name           string         `json:"name"`
	Description    string         `json:"description,omitempty"`
	InputSchema    any            `json:"input_schema,omitempty"`
	Tags           []string       `json:"tags,omitempty"`
	ReadOnly       bool           `json:"read_only"`
	Destructive    bool           `json:"destructive"`
	TimeoutMS      uint32         `json:"timeout_ms,omitempty"`
	MaxLogEntries  uint32         `json:"max_log_entries,omitempty"`
	MaxResultBytes uint64         `json:"max_result_bytes,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	Revision       uint64         `json:"revision"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

type managedToolDocument struct {
	Name           string         `json:"name"`
	Description    string         `json:"description,omitempty"`
	Script         string         `json:"script"`
	InputSchema    any            `json:"input_schema,omitempty"`
	Tags           []string       `json:"tags,omitempty"`
	ReadOnly       bool           `json:"read_only"`
	Destructive    bool           `json:"destructive"`
	TimeoutMS      uint32         `json:"timeout_ms,omitempty"`
	MaxLogEntries  uint32         `json:"max_log_entries,omitempty"`
	MaxResultBytes uint64         `json:"max_result_bytes,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	Revision       uint64         `json:"revision"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

type managedToolBundle struct {
	Schema     string        `json:"schema"`
	ExportedAt time.Time     `json:"exported_at"`
	Tools      []managedTool `json:"tools"`
}

type toolRegisterArgs struct {
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	Script          string          `json:"script"`
	InputSchema     json.RawMessage `json:"input_schema"`
	Tags            []string        `json:"tags"`
	ReadOnly        *bool           `json:"read_only"`
	Destructive     *bool           `json:"destructive"`
	TimeoutMS       Uint32          `json:"timeout_ms"`
	MaxLogEntries   Uint32          `json:"max_log_entries"`
	MaxResultBytes  Uint64          `json:"max_result_bytes"`
	Metadata        map[string]any  `json:"metadata"`
	ReplaceExisting bool            `json:"replace_existing"`
}

type toolUpdateArgs struct {
	Name           string          `json:"name"`
	Description    *string         `json:"description"`
	Script         *string         `json:"script"`
	InputSchema    json.RawMessage `json:"input_schema"`
	Tags           []string        `json:"tags"`
	ReadOnly       *bool           `json:"read_only"`
	Destructive    *bool           `json:"destructive"`
	TimeoutMS      *Uint32         `json:"timeout_ms"`
	MaxLogEntries  *Uint32         `json:"max_log_entries"`
	MaxResultBytes *Uint64         `json:"max_result_bytes"`
	Metadata       map[string]any  `json:"metadata"`
}

type toolNameArgs struct {
	Name string `json:"name"`
}

type toolListArgs struct {
	Tags []string `json:"tags"`
}

type toolExportArgs struct {
	Names []string `json:"names"`
}

type toolImportArgs struct {
	Tools           []managedTool      `json:"tools"`
	Bundle          *managedToolBundle `json:"bundle"`
	ReplaceExisting bool               `json:"replace_existing"`
}

type toolExecuteArgs struct {
	Name           string         `json:"name"`
	Args           map[string]any `json:"args"`
	TimeoutMS      Uint32         `json:"timeout_ms"`
	MaxLogEntries  Uint32         `json:"max_log_entries"`
	MaxResultBytes Uint64         `json:"max_result_bytes"`
}

type managedToolDatabase struct {
	Schema string        `json:"schema"`
	Tools  []managedTool `json:"tools"`
}

func (a *App) initManagedTools() error {
	if a.tools == nil {
		a.tools = map[string]*managedTool{}
	}
	if a.config.ToolDatabasePath == "" {
		return nil
	}
	loaded, err := loadManagedToolDatabase(a.config.ToolDatabasePath)
	if err != nil {
		return err
	}
	a.tools = loaded
	return nil
}

func (a *App) handleToolRegister(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args toolRegisterArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	now := time.Now().UTC()
	tool, err := toolFromRegisterArgs(args, now)
	if err != nil {
		return toolError(err)
	}
	var summary managedToolSummary
	if err := a.mutateManagedTools(func(tools map[string]*managedTool) error {
		if existing, ok := tools[tool.Name]; ok {
			if !args.ReplaceExisting {
				return fmt.Errorf("tool %q already exists", tool.Name)
			}
			tool.CreatedAt = existing.CreatedAt
			tool.Revision = existing.Revision + 1
		}
		copyTool := cloneManagedTool(tool)
		tools[tool.Name] = &copyTool
		summary = managedToolSummaryFor(tool)
		return nil
	}); err != nil {
		return toolError(err)
	}
	return jsonResult(map[string]any{"ok": true, "tool": summary})
}

func (a *App) handleToolUpdate(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args toolUpdateArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	if err := validateManagedToolName(args.Name); err != nil {
		return toolError(err)
	}
	var summary managedToolSummary
	now := time.Now().UTC()
	if err := a.mutateManagedTools(func(tools map[string]*managedTool) error {
		current, ok := tools[args.Name]
		if !ok {
			return fmt.Errorf("tool %q does not exist", args.Name)
		}
		updated := cloneManagedTool(*current)
		if args.Description != nil {
			updated.Description = *args.Description
		}
		if args.Script != nil {
			updated.Script = *args.Script
		}
		if args.InputSchema != nil {
			updated.InputSchema = cloneRawMessage(args.InputSchema)
		}
		if args.Tags != nil {
			updated.Tags = append([]string(nil), args.Tags...)
		}
		if args.ReadOnly != nil {
			updated.ReadOnly = *args.ReadOnly
		}
		if args.Destructive != nil {
			updated.Destructive = *args.Destructive
		}
		if args.TimeoutMS != nil {
			updated.TimeoutMS = uint32(*args.TimeoutMS)
		}
		if args.MaxLogEntries != nil {
			updated.MaxLogEntries = uint32(*args.MaxLogEntries)
		}
		if args.MaxResultBytes != nil {
			updated.MaxResultBytes = uint64(*args.MaxResultBytes)
		}
		if args.Metadata != nil {
			updated.Metadata = args.Metadata
		}
		updated.UpdatedAt = now
		updated.Revision++
		if err := validateManagedTool(&updated); err != nil {
			return err
		}
		tools[updated.Name] = &updated
		summary = managedToolSummaryFor(updated)
		return nil
	}); err != nil {
		return toolError(err)
	}
	return jsonResult(map[string]any{"ok": true, "tool": summary})
}

func (a *App) handleToolList(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args toolListArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	filter, err := normalizeTags(args.Tags)
	if err != nil {
		return toolError(err)
	}
	a.mu.Lock()
	tools := a.managedToolSummariesLocked(filter)
	storage := a.managedToolStorageLocked()
	a.mu.Unlock()
	return jsonResult(map[string]any{"ok": true, "count": len(tools), "storage": storage, "tools": tools})
}

func (a *App) handleToolRead(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args toolNameArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	if err := validateManagedToolName(args.Name); err != nil {
		return toolError(err)
	}
	a.mu.Lock()
	tool, ok := a.tools[args.Name]
	if ok {
		copyTool := cloneManagedTool(*tool)
		a.mu.Unlock()
		return jsonResult(map[string]any{"ok": true, "tool": managedToolDocumentFor(copyTool)})
	}
	a.mu.Unlock()
	return toolError(fmt.Errorf("tool %q does not exist", args.Name))
}

func (a *App) handleToolExport(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args toolExportArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	names := append([]string(nil), args.Names...)
	for _, name := range names {
		if err := validateManagedToolName(name); err != nil {
			return toolError(err)
		}
	}
	a.mu.Lock()
	tools, err := a.managedToolExportLocked(names)
	a.mu.Unlock()
	if err != nil {
		return toolError(err)
	}
	bundle := managedToolBundle{Schema: toolBundleSchema, ExportedAt: time.Now().UTC(), Tools: tools}
	return jsonResult(bundle)
}

func (a *App) handleToolImport(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args toolImportArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	tools := args.Tools
	if args.Bundle != nil {
		if args.Bundle.Schema != "" && args.Bundle.Schema != toolBundleSchema {
			return toolError(fmt.Errorf("unsupported tool bundle schema %q", args.Bundle.Schema))
		}
		if len(tools) > 0 {
			return toolError(errors.New("provide either tools or bundle, not both"))
		}
		tools = args.Bundle.Tools
	}
	if len(tools) == 0 {
		return toolError(errors.New("at least one tool is required"))
	}
	validated := make([]managedTool, 0, len(tools))
	seen := map[string]struct{}{}
	now := time.Now().UTC()
	for _, tool := range tools {
		if tool.CreatedAt.IsZero() {
			tool.CreatedAt = now
		}
		if tool.UpdatedAt.IsZero() {
			tool.UpdatedAt = now
		}
		if tool.Revision == 0 {
			tool.Revision = 1
		}
		if err := validateManagedTool(&tool); err != nil {
			return toolError(err)
		}
		if _, ok := seen[tool.Name]; ok {
			return toolError(fmt.Errorf("duplicate imported tool %q", tool.Name))
		}
		seen[tool.Name] = struct{}{}
		validated = append(validated, cloneManagedTool(tool))
	}
	imported := make([]managedToolSummary, 0, len(validated))
	if err := a.mutateManagedTools(func(current map[string]*managedTool) error {
		for _, tool := range validated {
			if _, ok := current[tool.Name]; ok && !args.ReplaceExisting {
				return fmt.Errorf("tool %q already exists", tool.Name)
			}
		}
		for _, tool := range validated {
			copyTool := cloneManagedTool(tool)
			current[tool.Name] = &copyTool
			imported = append(imported, managedToolSummaryFor(copyTool))
		}
		return nil
	}); err != nil {
		return toolError(err)
	}
	return jsonResult(map[string]any{"ok": true, "count": len(imported), "tools": imported})
}

func (a *App) handleToolDelete(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args toolNameArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	if err := validateManagedToolName(args.Name); err != nil {
		return toolError(err)
	}
	if err := a.mutateManagedTools(func(tools map[string]*managedTool) error {
		if _, ok := tools[args.Name]; !ok {
			return fmt.Errorf("tool %q does not exist", args.Name)
		}
		delete(tools, args.Name)
		return nil
	}); err != nil {
		return toolError(err)
	}
	return jsonResult(map[string]any{"ok": true, "deleted": args.Name})
}

func (a *App) handleToolExecute(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args toolExecuteArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	if err := validateManagedToolName(args.Name); err != nil {
		return toolError(err)
	}
	a.mu.Lock()
	tool, ok := a.tools[args.Name]
	if ok {
		copyTool := cloneManagedTool(*tool)
		a.mu.Unlock()
		evalArgs := evalArgs{
			Script:         copyTool.Script,
			Args:           args.Args,
			TimeoutMS:      Uint32(firstNonZeroUint32(uint32(args.TimeoutMS), copyTool.TimeoutMS)),
			MaxLogEntries:  Uint32(firstNonZeroUint32(uint32(args.MaxLogEntries), copyTool.MaxLogEntries)),
			MaxResultBytes: Uint64(firstNonZeroUint64(uint64(args.MaxResultBytes), copyTool.MaxResultBytes)),
		}
		return a.runEval(ctx, evalArgs)
	}
	a.mu.Unlock()
	return toolError(fmt.Errorf("tool %q does not exist", args.Name))
}

func toolFromRegisterArgs(args toolRegisterArgs, now time.Time) (managedTool, error) {
	readOnly := false
	if args.ReadOnly != nil {
		readOnly = *args.ReadOnly
	}
	destructive := true
	if args.Destructive != nil {
		destructive = *args.Destructive
	}
	tool := managedTool{
		Name:           args.Name,
		Description:    args.Description,
		Script:         args.Script,
		InputSchema:    cloneRawMessage(args.InputSchema),
		Tags:           append([]string(nil), args.Tags...),
		ReadOnly:       readOnly,
		Destructive:    destructive,
		TimeoutMS:      uint32(args.TimeoutMS),
		MaxLogEntries:  uint32(args.MaxLogEntries),
		MaxResultBytes: uint64(args.MaxResultBytes),
		Metadata:       args.Metadata,
		Revision:       1,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := validateManagedTool(&tool); err != nil {
		return managedTool{}, err
	}
	return tool, nil
}

func validateManagedTool(tool *managedTool) error {
	if err := validateManagedToolName(tool.Name); err != nil {
		return err
	}
	tool.Description = strings.TrimSpace(tool.Description)
	if len(tool.Description) > 4096 {
		return fmt.Errorf("tool %q description exceeds 4096 bytes", tool.Name)
	}
	if strings.TrimSpace(tool.Script) == "" {
		return fmt.Errorf("tool %q script is required", tool.Name)
	}
	if len(tool.Script) > maxManagedToolScriptSize {
		return fmt.Errorf("tool %q script is %d bytes, exceeding maximum %d", tool.Name, len(tool.Script), maxManagedToolScriptSize)
	}
	inputSchema, err := normalizeInputSchema(tool.InputSchema)
	if err != nil {
		return fmt.Errorf("tool %q input_schema: %w", tool.Name, err)
	}
	tool.InputSchema = inputSchema
	tags, err := normalizeTags(tool.Tags)
	if err != nil {
		return fmt.Errorf("tool %q tags: %w", tool.Name, err)
	}
	tool.Tags = tags
	metadata, err := normalizeMetadata(tool.Metadata)
	if err != nil {
		return fmt.Errorf("tool %q metadata: %w", tool.Name, err)
	}
	tool.Metadata = metadata
	if tool.TimeoutMS > maxEvalTimeoutMS {
		return fmt.Errorf("tool %q timeout_ms %d exceeds maximum %d", tool.Name, tool.TimeoutMS, maxEvalTimeoutMS)
	}
	if tool.MaxLogEntries > maxEvalLogEntries {
		return fmt.Errorf("tool %q max_log_entries %d exceeds maximum %d", tool.Name, tool.MaxLogEntries, maxEvalLogEntries)
	}
	if tool.CreatedAt.IsZero() {
		tool.CreatedAt = time.Now().UTC()
	}
	if tool.UpdatedAt.IsZero() {
		tool.UpdatedAt = tool.CreatedAt
	}
	if tool.Revision == 0 {
		tool.Revision = 1
	}
	return nil
}

func validateManagedToolName(name string) error {
	if err := validateName("tool", name); err != nil {
		return err
	}
	if isReservedManagedToolName(name) {
		return fmt.Errorf("tool name %q is reserved for built-in MCP tools", name)
	}
	return nil
}

func isReservedManagedToolName(name string) bool {
	for _, spec := range toolSummaryRegistry() {
		if spec.name == name {
			return true
		}
	}
	return false
}

func normalizeInputSchema(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return nil, nil
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, err
	}
	if _, ok := decoded.(map[string]any); !ok {
		return nil, errors.New("must be a JSON object")
	}
	data, err := json.Marshal(decoded)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(data), nil
}

func normalizeTags(tags []string) ([]string, error) {
	if len(tags) == 0 {
		return nil, nil
	}
	if len(tags) > maxManagedToolTags {
		return nil, fmt.Errorf("too many tags: %d exceeds %d", len(tags), maxManagedToolTags)
	}
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(tags))
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if err := validateName("tag", tag); err != nil {
			return nil, err
		}
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		normalized = append(normalized, tag)
	}
	return normalized, nil
}

func normalizeMetadata(metadata map[string]any) (map[string]any, error) {
	if len(metadata) == 0 {
		return nil, nil
	}
	value := jsonSafeValue(metadata)
	if err := ensureJSONSize(value, maxManagedToolMetaSize); err != nil {
		return nil, err
	}
	decoded, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("must be a JSON object")
	}
	return decoded, nil
}

func (a *App) mutateManagedTools(fn func(map[string]*managedTool) error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	tools := cloneManagedToolMap(a.tools)
	if err := fn(tools); err != nil {
		return err
	}
	if a.config.ToolDatabasePath != "" {
		if err := saveManagedToolDatabase(a.config.ToolDatabasePath, tools); err != nil {
			return err
		}
	}
	a.tools = tools
	return nil
}

func (a *App) managedToolStorageLocked() map[string]any {
	storage := map[string]any{"mode": "memory", "persistent": false}
	if a.config.ToolDatabasePath != "" {
		storage["mode"] = "json"
		storage["persistent"] = true
	}
	return storage
}

func (a *App) managedToolSummariesLocked(filter []string) []managedToolSummary {
	filterSet := map[string]struct{}{}
	for _, tag := range filter {
		filterSet[tag] = struct{}{}
	}
	summaries := make([]managedToolSummary, 0, len(a.tools))
	for _, tool := range a.tools {
		if len(filterSet) > 0 && !managedToolHasAllTags(tool, filterSet) {
			continue
		}
		summaries = append(summaries, managedToolSummaryFor(*tool))
	}
	sort.Slice(summaries, func(i, j int) bool { return summaries[i].Name < summaries[j].Name })
	return summaries
}

func (a *App) managedToolExportLocked(names []string) ([]managedTool, error) {
	if len(names) == 0 {
		tools := make([]managedTool, 0, len(a.tools))
		for _, tool := range a.tools {
			tools = append(tools, cloneManagedTool(*tool))
		}
		sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
		return tools, nil
	}
	tools := make([]managedTool, 0, len(names))
	seen := map[string]struct{}{}
	for _, name := range names {
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		tool, ok := a.tools[name]
		if !ok {
			return nil, fmt.Errorf("tool %q does not exist", name)
		}
		tools = append(tools, cloneManagedTool(*tool))
	}
	return tools, nil
}

func managedToolHasAllTags(tool *managedTool, filter map[string]struct{}) bool {
	tags := map[string]struct{}{}
	for _, tag := range tool.Tags {
		tags[tag] = struct{}{}
	}
	for tag := range filter {
		if _, ok := tags[tag]; !ok {
			return false
		}
	}
	return true
}

func managedToolSummaryFor(tool managedTool) managedToolSummary {
	return managedToolSummary{
		Name:           tool.Name,
		Description:    tool.Description,
		InputSchema:    rawMessageValue(tool.InputSchema),
		Tags:           append([]string(nil), tool.Tags...),
		ReadOnly:       tool.ReadOnly,
		Destructive:    tool.Destructive,
		TimeoutMS:      tool.TimeoutMS,
		MaxLogEntries:  tool.MaxLogEntries,
		MaxResultBytes: tool.MaxResultBytes,
		Metadata:       cloneMetadata(tool.Metadata),
		Revision:       tool.Revision,
		CreatedAt:      tool.CreatedAt,
		UpdatedAt:      tool.UpdatedAt,
	}
}

func managedToolDocumentFor(tool managedTool) managedToolDocument {
	return managedToolDocument{
		Name:           tool.Name,
		Description:    tool.Description,
		Script:         tool.Script,
		InputSchema:    rawMessageValue(tool.InputSchema),
		Tags:           append([]string(nil), tool.Tags...),
		ReadOnly:       tool.ReadOnly,
		Destructive:    tool.Destructive,
		TimeoutMS:      tool.TimeoutMS,
		MaxLogEntries:  tool.MaxLogEntries,
		MaxResultBytes: tool.MaxResultBytes,
		Metadata:       cloneMetadata(tool.Metadata),
		Revision:       tool.Revision,
		CreatedAt:      tool.CreatedAt,
		UpdatedAt:      tool.UpdatedAt,
	}
}

func rawMessageValue(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil
	}
	return decoded
}

func cloneManagedToolMap(in map[string]*managedTool) map[string]*managedTool {
	out := make(map[string]*managedTool, len(in))
	for name, tool := range in {
		copyTool := cloneManagedTool(*tool)
		out[name] = &copyTool
	}
	return out
}

func cloneManagedTool(tool managedTool) managedTool {
	tool.InputSchema = cloneRawMessage(tool.InputSchema)
	tool.Tags = append([]string(nil), tool.Tags...)
	tool.Metadata = cloneMetadata(tool.Metadata)
	return tool
}

func cloneRawMessage(raw json.RawMessage) json.RawMessage {
	if raw == nil {
		return nil
	}
	return append(json.RawMessage(nil), raw...)
}

func cloneMetadata(metadata map[string]any) map[string]any {
	if len(metadata) == 0 {
		return nil
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return map[string]any{}
	}
	return out
}

func loadManagedToolDatabase(file string) (map[string]*managedTool, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]*managedTool{}, nil
		}
		return nil, fmt.Errorf("read tool database: %w", err)
	}
	var db managedToolDatabase
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("decode tool database: %w", err)
	}
	if db.Schema != "" && db.Schema != toolBundleSchema {
		return nil, fmt.Errorf("unsupported tool database schema %q", db.Schema)
	}
	tools := map[string]*managedTool{}
	for _, tool := range db.Tools {
		if err := validateManagedTool(&tool); err != nil {
			return nil, fmt.Errorf("invalid tool database entry: %w", err)
		}
		if _, ok := tools[tool.Name]; ok {
			return nil, fmt.Errorf("duplicate tool database entry %q", tool.Name)
		}
		copyTool := cloneManagedTool(tool)
		tools[tool.Name] = &copyTool
	}
	return tools, nil
}

func saveManagedToolDatabase(file string, tools map[string]*managedTool) error {
	dir := filepath.Dir(file)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create tool database directory: %w", err)
	}
	items := make([]managedTool, 0, len(tools))
	for _, tool := range tools {
		items = append(items, cloneManagedTool(*tool))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	db := managedToolDatabase{Schema: toolBundleSchema, Tools: items}
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return fmt.Errorf("encode tool database: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(file)+"-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary tool database: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary tool database: %w", err)
	}
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temporary tool database: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary tool database: %w", err)
	}
	if err := os.Rename(tmpName, file); err != nil {
		return fmt.Errorf("replace tool database: %w", err)
	}
	return nil
}

func firstNonZeroUint32(values ...uint32) uint32 {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func firstNonZeroUint64(values ...uint64) uint64 {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}
