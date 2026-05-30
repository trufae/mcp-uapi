// name: ebpf_socket_filter_self_contained
// title: Self-contained eBPF socket filter loader
// description: Loads a built-in socket_filter_pass program through the JavaScript API, runs it with Program.Test, and cleans up managed eBPF state. Requires kernel eBPF support and permission to load socket filters.
// tags: ebpf, socket-filter, program-test, self-contained

var prefix = args.prefix || "ebpfDemo";
var progHandle = prefix + "Prog";
var payload = args.payload || "hello from mcp-uapi";
var result = {
  ok: false,
  info: sys.ebpfInfo(),
  feature: sys.ebpfFeatureProbe({kind: "program_type", type: "socket_filter"})
};

function closeProgram() {
  var closed = sys.ebpfProgramClose({program: progHandle});
  result.cleanup = result.cleanup || [];
  result.cleanup.push({program: progHandle, close: closed});
}

try {
  if (result.feature && result.feature.ok && result.feature.supported === false) {
    result.error = "socket_filter eBPF programs are not supported by this kernel";
    return result;
  }

  var prog = sys.ebpfProgramLoad({
    handle: progHandle,
    kind: "socket_filter_pass",
    log_level: "BPF_LOG_LEVEL1",
    log_size_start: 65536
  });
  result.program = prog;
  if (!prog.ok) {
    result.error = "program load failed";
    return result;
  }

  var test = sys.ebpfProgramTest({
    program: progHandle,
    data_utf8: payload,
    encoding: "utf8"
  });
  result.test = test;
  result.ok = test.ok === true;
  return result;
} finally {
  if (result.program && result.program.ok) {
    closeProgram();
  }
}
