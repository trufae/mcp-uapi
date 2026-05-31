package mcpserver

const schemaNoArgs = `{"type":"object","properties":{},"additionalProperties":false}`

const schemaCapabilities = schemaNoArgs

const schemaConstants = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"group":{"type":"string","description":"Optional group name such as open_flags, socket, mmap, epoll, poll, signal, wait, ioctl, prctl, errno."}}
}`

const schemaErrno = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"errno":{"type":["integer","string"]},"name":{"type":"string"}}
}`

const schemaOpen = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"path":{"type":"string"},"flags":{"type":["integer","string"],"default":"O_RDONLY|O_CLOEXEC"},"mode":{"type":["integer","string"],"default":"0600"},"handle":{"type":"string","description":"Optional stable handle name."}},
  "required":["path"]
}`

const schemaFDRef = `"handle":{"type":"string"},"fd":{"type":"integer","description":"Raw FD or a known managed FD. Raw FDs require --allow-raw-fd."}`

const schemaClose = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{` + schemaFDRef + `}
}`

const schemaRead = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{` + schemaFDRef + `,"length":{"type":["integer","string"]},"encoding":{"type":"string","enum":["base64","hex","utf8"],"default":"base64"}},
  "required":["length"]
}`

const schemaPRead = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{` + schemaFDRef + `,"offset":{"type":["integer","string"]},"length":{"type":["integer","string"]},"encoding":{"type":"string","enum":["base64","hex","utf8"],"default":"base64"}},
  "required":["offset","length"]
}`

const schemaWrite = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{` + schemaFDRef + `,"data_base64":{"type":"string"},"data_hex":{"type":"string"},"data_utf8":{"type":"string"},"buffer":{"type":"string"},"buffer_offset":{"type":["integer","string"],"default":0},"length":{"type":["integer","string"],"description":"Optional length when writing from a managed buffer."}}
}`

const schemaPWrite = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{` + schemaFDRef + `,"offset":{"type":["integer","string"]},"data_base64":{"type":"string"},"data_hex":{"type":"string"},"data_utf8":{"type":"string"},"buffer":{"type":"string"},"buffer_offset":{"type":["integer","string"],"default":0},"length":{"type":["integer","string"]}},
  "required":["offset"]
}`

const schemaLseek = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{` + schemaFDRef + `,"offset":{"type":["integer","string"]},"whence":{"type":["integer","string"],"default":"SEEK_SET"}},
  "required":["offset"]
}`

const schemaFstat = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{` + schemaFDRef + `}
}`

const schemaStat = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"path":{"type":"string"},"nofollow":{"type":"boolean","default":false}},
  "required":["path"]
}`

const schemaReadlink = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"path":{"type":"string"},"size":{"type":["integer","string"],"default":4096}},
  "required":["path"]
}`

const schemaBufferAlloc = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"name":{"type":"string"},"size":{"type":["integer","string"]},"replace_existing":{"type":"boolean","default":false}},
  "required":["name","size"]
}`

const schemaBufferFree = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"name":{"type":"string"}},
  "required":["name"]
}`

const schemaBufferInfo = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"name":{"type":"string"}}
}`

const schemaBufferWrite = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"name":{"type":"string"},"offset":{"type":["integer","string"],"default":0},"data_base64":{"type":"string"},"data_hex":{"type":"string"},"data_utf8":{"type":"string"},"fill":{"type":"object","additionalProperties":false,"properties":{"mode":{"type":"string","enum":["zero","value"],"default":"zero"},"length":{"type":["integer","string"]},"value":{"type":["integer","string"],"default":0}},"required":["length"]}},
  "required":["name"]
}`

const schemaBufferRead = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"name":{"type":"string"},"offset":{"type":["integer","string"],"default":0},"length":{"type":["integer","string"]},"encoding":{"type":"string","enum":["base64","hex","utf8"],"default":"base64"}},
  "required":["name","length"]
}`

const schemaMmap = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"fd_handle":{"type":"string"},"fd":{"type":"integer","description":"File FD for file-backed mappings. Omit for MAP_ANONYMOUS."},"length":{"type":["integer","string"]},"prot":{"type":["integer","string"],"default":"PROT_READ|PROT_WRITE"},"flags":{"type":["integer","string"],"default":"MAP_PRIVATE|MAP_ANONYMOUS"},"offset":{"type":["integer","string"],"default":0},"handle":{"type":"string"}},
  "required":["length"]
}`

const schemaMunmap = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"mapping":{"type":"string"}},
  "required":["mapping"]
}`

const schemaMprotect = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"mapping":{"type":"string"},"offset":{"type":["integer","string"],"default":0},"length":{"type":["integer","string"]},"prot":{"type":["integer","string"]}},
  "required":["mapping","prot"]
}`

const schemaMsync = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"mapping":{"type":"string"},"offset":{"type":["integer","string"],"default":0},"length":{"type":["integer","string"]},"flags":{"type":["integer","string"],"default":"MS_SYNC"}},
  "required":["mapping"]
}`

const schemaMadvise = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"mapping":{"type":"string"},"offset":{"type":["integer","string"],"default":0},"length":{"type":["integer","string"]},"advice":{"type":["integer","string"]}},
  "required":["mapping","advice"]
}`

const schemaMemRead = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"mapping":{"type":"string"},"offset":{"type":["integer","string"],"default":0},"length":{"type":["integer","string"]},"encoding":{"type":"string","enum":["base64","hex","utf8"],"default":"base64"}},
  "required":["mapping","length"]
}`

const schemaMemWrite = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"mapping":{"type":"string"},"offset":{"type":["integer","string"],"default":0},"data_base64":{"type":"string"},"data_hex":{"type":"string"},"data_utf8":{"type":"string"},"buffer":{"type":"string"},"buffer_offset":{"type":["integer","string"],"default":0},"length":{"type":["integer","string"]}},
  "required":["mapping"]
}`

const schemaSockaddr = `"sockaddr":{"type":"object","additionalProperties":false,"properties":{"family":{"type":"string","enum":["unix","inet4","inet6","netlink"]},"path":{"type":"string"},"ip":{"type":"string"},"port":{"type":"integer"},"zone_id":{"type":"integer"},"pid":{"type":"integer"},"groups":{"type":["integer","string"]}},"required":["family"]}`

const schemaSocket = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"domain":{"type":["integer","string"]},"type":{"type":["integer","string"]},"protocol":{"type":["integer","string"],"default":0},"handle":{"type":"string"}},
  "required":["domain","type"]
}`

const schemaSocketpair = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"domain":{"type":["integer","string"],"default":"AF_UNIX"},"type":{"type":["integer","string"],"default":"SOCK_STREAM|SOCK_CLOEXEC"},"protocol":{"type":["integer","string"],"default":0},"handles":{"type":"array","items":{"type":"string"},"minItems":2,"maxItems":2}}
}`

const schemaBindConnect = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{` + schemaFDRef + `,` + schemaSockaddr + `},
  "required":["sockaddr"]
}`

const schemaListen = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{` + schemaFDRef + `,"backlog":{"type":["integer","string"],"default":128}}
}`

const schemaAccept = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"listener_handle":{"type":"string"},"listener_fd":{"type":"integer"},"flags":{"type":["integer","string"],"default":"SOCK_CLOEXEC"},"handle":{"type":"string"}}
}`

const schemaSendto = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{` + schemaFDRef + `,"flags":{"type":["integer","string"],"default":0},` + schemaSockaddr + `,"data_base64":{"type":"string"},"data_hex":{"type":"string"},"data_utf8":{"type":"string"},"buffer":{"type":"string"},"buffer_offset":{"type":["integer","string"],"default":0},"length":{"type":["integer","string"]}}
}`

const schemaRecvfrom = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{` + schemaFDRef + `,"length":{"type":["integer","string"]},"flags":{"type":["integer","string"],"default":0},"encoding":{"type":"string","enum":["base64","hex","utf8"],"default":"base64"}},
  "required":["length"]
}`

const schemaSockName = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{` + schemaFDRef + `}
}`

const schemaSockOptInt = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{` + schemaFDRef + `,"level":{"type":["integer","string"]},"opt":{"type":["integer","string"]},"value":{"type":["integer","string"]}},
  "required":["level","opt"]
}`

const schemaShutdown = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{` + schemaFDRef + `,"how":{"type":["integer","string"],"default":"SHUT_RDWR"}}
}`

const schemaPoll = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"fds":{"type":"array","items":{"type":"object","additionalProperties":false,"properties":{"handle":{"type":"string"},"fd":{"type":"integer"},"events":{"type":["integer","string"]}},"required":["events"]}},"timeout_ms":{"type":["integer","string"],"default":0}},
  "required":["fds"]
}`

const schemaEpollCreate = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"flags":{"type":["integer","string"],"default":"EPOLL_CLOEXEC"},"handle":{"type":"string"}}
}`

const schemaEpollCtl = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"epoll_handle":{"type":"string"},"epoll_fd":{"type":"integer"},"op":{"type":["integer","string"]},"target_handle":{"type":"string"},"target_fd":{"type":"integer"},"events":{"type":["integer","string"],"default":"EPOLLIN"},"data":{"type":["integer","string"],"description":"Optional event data. Defaults to the target FD."}},
  "required":["op"]
}`

const schemaEpollWait = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"epoll_handle":{"type":"string"},"epoll_fd":{"type":"integer"},"max_events":{"type":["integer","string"],"default":16},"timeout_ms":{"type":["integer","string"],"default":0}}
}`

const schemaKill = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"pid":{"type":"integer"},"signal":{"type":["integer","string"]}},
  "required":["pid","signal"]
}`

const schemaWait4 = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"pid":{"type":"integer","default":-1},"options":{"type":["integer","string"],"default":0},"timeout_ms":{"type":["integer","string"],"default":0}}
}`

const schemaPtraceAttach = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"pid":{"type":"integer"},"wait":{"type":"boolean","default":true},"timeout_ms":{"type":["integer","string"],"default":5000}},
  "required":["pid"]
}`

const schemaPtraceDetach = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"pid":{"type":"integer"}},
  "required":["pid"]
}`

const schemaPtraceRead = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"pid":{"type":"integer"},"address":{"type":["integer","string"]},"length":{"type":["integer","string"]},"encoding":{"type":"string","enum":["base64","hex","utf8"],"default":"base64"}},
  "required":["pid","address","length"]
}`

const schemaPtraceWrite = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"pid":{"type":"integer"},"address":{"type":["integer","string"]},"data_base64":{"type":"string"},"data_hex":{"type":"string"},"data_utf8":{"type":"string"}},
  "required":["pid","address"]
}`

const schemaPtraceSignal = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"pid":{"type":"integer"},"signal":{"type":["integer","string"],"default":0}},
  "required":["pid"]
}`

const schemaPtraceOptions = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"pid":{"type":"integer"},"options":{"type":["integer","string"],"default":0}},
  "required":["pid","options"]
}`

const schemaIoctl = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{` + schemaFDRef + `,"request":{"type":["integer","string"]},"arg":{"type":["integer","string"],"default":0},"buffer":{"type":"string"},"buffer_offset":{"type":["integer","string"],"default":0},"buffer_length":{"type":["integer","string"]}},
  "required":["request"]
}`

const schemaPrctl = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"option":{"type":["integer","string"]},"arg2":{"type":["integer","string"],"default":0},"arg3":{"type":["integer","string"],"default":0},"arg4":{"type":["integer","string"],"default":0},"arg5":{"type":["integer","string"],"default":0}},
  "required":["option"]
}`

const schemaEval = `{
  "type":"object",
  "description":"Execute JavaScript inside a function body. Read MCP resources uapi://agent-guide, uapi://scripting-api, and uapi://api-reference outside eval. Inside eval use sys.* or uapi.*; uapi.request, sys.request, fetch, require, and import are not available.",
  "additionalProperties":false,
  "properties":{"script":{"type":"string","description":"JavaScript source. Globals: args, console, print, sys, uapi, os, io."},"args":{"type":"object"},"timeout_ms":{"type":["integer","string"],"default":5000},"max_log_entries":{"type":["integer","string"],"default":200},"max_result_bytes":{"type":["integer","string"]}},
  "required":["script"]
}`

const schemaToolRegister = `{
  "type":"object",
  "description":"Register a reusable eval script as a named managed tool.",
  "additionalProperties":false,
  "properties":{"name":{"type":"string","description":"Stable tool name using A-Za-z0-9_.:-."},"description":{"type":"string"},"script":{"type":"string","description":"JavaScript source run inside eval with caller args."},"input_schema":{"type":"object","description":"Optional JSON Schema object describing args accepted by the script."},"tags":{"type":"array","items":{"type":"string"},"maxItems":32},"read_only":{"type":"boolean","default":false},"destructive":{"type":"boolean","default":true},"timeout_ms":{"type":["integer","string"]},"max_log_entries":{"type":["integer","string"]},"max_result_bytes":{"type":["integer","string"]},"metadata":{"type":"object"},"replace_existing":{"type":"boolean","default":false}},
  "required":["name","script"]
}`

const schemaToolUpdate = `{
  "type":"object",
  "description":"Update an existing managed eval tool. Omitted fields keep their current value; null input_schema clears it.",
  "additionalProperties":false,
  "properties":{"name":{"type":"string"},"description":{"type":"string"},"script":{"type":"string"},"input_schema":{"type":["object","null"]},"tags":{"type":"array","items":{"type":"string"},"maxItems":32},"read_only":{"type":"boolean"},"destructive":{"type":"boolean"},"timeout_ms":{"type":["integer","string"]},"max_log_entries":{"type":["integer","string"]},"max_result_bytes":{"type":["integer","string"]},"metadata":{"type":"object"}},
  "required":["name"]
}`

const schemaToolExecute = `{
  "type":"object",
  "description":"Execute a registered managed eval tool by name. args becomes the script's args global.",
  "additionalProperties":false,
  "properties":{"name":{"type":"string"},"args":{"type":"object"},"timeout_ms":{"type":["integer","string"],"description":"Optional per-call override."},"max_log_entries":{"type":["integer","string"],"description":"Optional per-call override."},"max_result_bytes":{"type":["integer","string"],"description":"Optional per-call override."}},
  "required":["name"]
}`

const schemaToolList = `{
  "type":"object",
  "description":"List registered managed eval tools without script bodies. Optional tags filter requires all listed tags.",
  "additionalProperties":false,
  "properties":{"tags":{"type":"array","items":{"type":"string"},"maxItems":32}}
}`

const schemaToolRead = `{
  "type":"object",
  "description":"Read one registered managed eval tool including its script body.",
  "additionalProperties":false,
  "properties":{"name":{"type":"string"}},
  "required":["name"]
}`

const schemaToolExport = `{
  "type":"object",
  "description":"Export all registered managed eval tools, or a selected set, as a portable JSON bundle.",
  "additionalProperties":false,
  "properties":{"names":{"type":"array","items":{"type":"string"}}}
}`

const schemaManagedToolImportObject = `{
  "type":"object",
  "additionalProperties":false,
  "properties":{"name":{"type":"string"},"description":{"type":"string"},"script":{"type":"string"},"input_schema":{"type":"object"},"tags":{"type":"array","items":{"type":"string"},"maxItems":32},"read_only":{"type":"boolean"},"destructive":{"type":"boolean"},"timeout_ms":{"type":["integer","string"]},"max_log_entries":{"type":["integer","string"]},"max_result_bytes":{"type":["integer","string"]},"metadata":{"type":"object"},"revision":{"type":"integer"},"created_at":{"type":"string"},"updated_at":{"type":"string"}},
  "required":["name","script"]
}`

const schemaToolImport = `{
  "type":"object",
  "description":"Import managed eval tools from an exported bundle or a raw tools array.",
  "additionalProperties":false,
  "properties":{"tools":{"type":"array","items":` + schemaManagedToolImportObject + `},"bundle":{"type":"object","additionalProperties":false,"properties":{"schema":{"type":"string"},"exported_at":{"type":"string"},"tools":{"type":"array","items":` + schemaManagedToolImportObject + `}},"required":["tools"]},"replace_existing":{"type":"boolean","default":false}}
}`

const schemaToolDelete = `{
  "type":"object",
  "description":"Delete a registered managed eval tool.",
  "additionalProperties":false,
  "properties":{"name":{"type":"string"}},
  "required":["name"]
}`
