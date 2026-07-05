# GhidrAssistMCP

A powerful Ghidra extension that provides an MCP (Model Context Protocol) server, enabling AI assistants and other tools to interact with Ghidra's reverse engineering capabilities through a standardized API.

## Overview

GhidrAssistMCP bridges the gap between AI-powered analysis tools and Ghidra's comprehensive reverse engineering platform. By implementing the Model Context Protocol, this extension allows external AI assistants, automated analysis tools, and custom scripts to seamlessly interact with Ghidra's analysis capabilities.

### Key Features

- **MCP Server Integration**: Full Model Context Protocol server implementation using official SDK
- **Python 3 Scripting Support**: Provides an `eval_python` endpoint giving AI full scriptable access to the Ghidra API (when launched with PyGhidra)
- **Dual HTTP Transports**: Supports SSE and Streamable HTTP transports for maximum client compatibility
- **54 Built-in Tools**: Comprehensive set of analysis tools with action-based consolidation for cleaner APIs
- **6 MCP Resources**: Static data resources for program info, functions, strings, imports, exports, and segments
- **7 MCP Prompts**: Pre-built analysis prompts for common reverse engineering tasks
- **Result Caching**: Intelligent caching system to improve performance for repeated queries
- **Async Task Support**: Long-running operations execute asynchronously with task management
- **Multi-Program Support**: Work with multiple open programs simultaneously using `program_name`; use `list_binaries` Project Path values to disambiguate duplicate filenames
- **Multi-Window Support**: Single MCP server shared across all CodeBrowser windows with intelligent focus tracking
- **Active Context Awareness**: Automatic detection of which binary window is in focus, with context hints in all tool responses
- **Configurable UI**: Easy-to-use interface for managing tools and monitoring activity
- **Real-time Logging**: Track all MCP requests and responses with detailed logging
- **Dynamic Tool Management**: Enable/disable tools individually with persistent settings

## Clients

Shameless self-promotion: [GhidrAssist](https://github.com/jtang613/GhidrAssist) supports GhidrAssistMCP right out of the box.

## Screenshots

![Screenshot](https://github.com/jtang613/GhidrAssistMCP/blob/master/res/Screenshot1.png)
![Screenshot](https://github.com/jtang613/GhidrAssistMCP/blob/master/res/Screenshot2.png)

## Installation

### Prerequisites

- **Ghidra 11.4+** (tested with Ghidra 12.1 Public)
- **An MCP Client (Like GhidrAssist)**

### Binary Release (Recommended)

1. **Download the latest release**:
   - Go to the [Releases page](https://github.com/jtang613/GhidrAssistMCP/releases)
   - Download the latest `.zip` file (e.g., `GhidrAssistMCP-v1.0.0.zip`)

2. **Install the extension**:
   - In Ghidra: **File → Install Extensions → Add Extension**
   - Select the downloaded ZIP file
   - Restart Ghidra when prompted

3. **Enable the plugin**:
   - **File → Configure → Configure Plugins**
   - Search for "GhidrAssistMCP"
   - Check the box to enable the plugin

### Building from Source

1. **Clone the repository**:

   ```bash
   git clone <repository-url>
   cd GhidrAssistMCP
   ```

2. **Point Gradle at your Ghidra install**:
   - Set `GHIDRA_INSTALL_DIR` (environment variable), or pass `-PGHIDRA_INSTALL_DIR=<path>` when you run Gradle.

3. **Build + install**:

   Ensure Ghidra isn't running and run:

   ```bash
   gradle installExtension
   ```

   This copies the built ZIP into your Ghidra install (`[GHIDRA_INSTALL_DIR]/Extensions/Ghidra`) and extracts it into your Ghidra **user** Extensions folder (replacing any existing extracted copy).

   If you need to override that location, pass `-PGHIDRA_USER_EXTENSIONS_DIR=<path>`.

4. **Restart / verify**:
   - Restart Ghidra.
   - If the plugin doesn't appear, enable it via **File → Configure → Configure Plugins** (search for "GhidrAssistMCP").

## Configuration

### Initial Setup

1. **Open the Control Panel**:
   - Window → GhidrAssistMCP (or use the toolbar icon)

2. **Configure Server Settings**:
   - **Host**: Default is `localhost`
   - **Port**: Default is `8080`
   - **Enable/Disable**: Toggle the MCP server on/off

### Tool Management

The Configuration tab allows you to:

- **View all available tools** (54 total)
- **Enable/disable individual tools** using checkboxes
- **Save configuration** to persist across sessions
- **Monitor tool status** in real-time

## Headless Mode Quickstart

GhidrAssistMCP can also be started from Ghidra's `analyzeHeadless` launcher. This is useful when you want MCP access to a program loaded in headless Ghidra without opening the CodeBrowser UI.

First, build and install the extension so Ghidra can load the compiled classes and bundled dependencies:

```bash
cd /path/to/GhidrAssistMCP

export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1_PUBLIC
gradle installExtension
```

Set paths for your Ghidra install and extracted user extension. On Linux, Ghidra user extensions usually live under `~/.config/ghidra/<ghidra_profile>/Extensions`:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1_PUBLIC
export GHIDRA_USER_EXTENSIONS_DIR="$HOME/.config/ghidra/ghidra_12.1_PUBLIC/Extensions"
export GHIDRASSISTMCP_EXT="$GHIDRA_USER_EXTENSIONS_DIR/GhidrAssistMCP"
```

Import a binary and start the MCP server as a headless pre-script:

```bash
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" /tmp/ghidra-projects McpHeadless \
  -import /path/to/binary \
  -scriptPath "$GHIDRASSISTMCP_EXT/ghidra_scripts" \
  -preScript GAMCPStartServerScript.java "host=127.0.0.1" "port=8080"
```

For a binary that is already imported into the project, use `-process` instead:

```bash
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" /tmp/ghidra-projects McpHeadless \
  -process binary_name \
  -scriptPath "$GHIDRASSISTMCP_EXT/ghidra_scripts" \
  -preScript GAMCPStartServerScript.java "host=127.0.0.1" "port=8080"
```

To keep a headless MCP session open after analysis completes, run the server as a post-script with wait mode:

```bash
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" /tmp/ghidra-projects McpHeadless \
  -process binary_name \
  -scriptPath "$GHIDRASSISTMCP_EXT/ghidra_scripts" \
  -postScript GAMCPStartServerScript.java "host=127.0.0.1" "port=8080" "wait=true"
```

MCP clients can connect to:

```text
Streamable HTTP: http://127.0.0.1:8080/mcp
```

The headless MCP server runs inside the `analyzeHeadless` JVM and uses the loaded `currentProgram`. The server holds a program consumer while it is running so MCP requests do not race against program database closure. Use `wait=true` when you want `analyzeHeadless` to stay open for interactive MCP clients; cancel the script or terminate the process to stop the server.

## Available Tools

GhidrAssistMCP provides 54 tools organized into categories. Several tools use an action-based API pattern where a single tool provides multiple related operations.

### Binary & Program Management

| Tool | Description |
| ---- | ----------- |
| `get_binary_info` | Get basic program information (name, architecture, compiler, etc.) |
| `list_binaries` | List all open programs across all CodeBrowser windows, including Project Path values for unambiguous `program_name` targeting |
| `open_program` | List/open project programs in CodeBrowser, with optional analysis prompt suppression and analysis-after-open task submission |
| `close_program` | Close an open CodeBrowser program; changed programs require `save=true` or `ignore_changes=true` |
| `save_program` | Save a program's pending changes to the Ghidra project (use after `eval_python`, which cannot save from inside its own transaction) |
| `import_file` | Import a host file into the current Ghidra project and optionally open it *(disabled by default)* |
| `project_files` | List or delete files/folders in the active Ghidra project; deletion requires `confirm=true` |
| `scripts` | List/read/write/delete/run Ghidra scripts *(disabled by default)* |
| `assemble_code` | Assemble instruction text at an address and optionally patch it into program memory |
| `patch_bytes` | Patch raw bytes in program memory at a given address |
| `export_program` | Export the current program to disk (`binary` or `original_file`) *(disabled by default)* |

> **Security-sensitive tools:** `import_file`, `scripts`, and `export_program` are disabled by default because they interact with the host filesystem or execute script code. Enable them explicitly in the plugin configuration UI when needed.
> `project_files` deletes entries from the active Ghidra project database, not the original imported host files, and requires `confirm=true`.

### Auto Analysis

| Tool | Description |
| ---- | ----------- |
| `analysis_options` | List/set/reset Auto Analysis options and save/apply/list/delete option presets for the current program |
| `analyze_program` | Run Auto Analysis on the current program or all open programs; supports full re-analysis, pending-changes analysis, address ranges, and option overrides |
| `analysis_control` | Query Auto Analysis status or request cancellation of queued analysis tasks |

#### `open_program` - Open / List Project Programs

Bootstrap a session from MCP without the Ghidra GUI. `import_file` (above, disabled by default) adds new binaries from disk.

| Action | Description |
| ------ | ----------- |
| `list` | List all programs in the current Ghidra project |
| `open` | Open a program in CodeBrowser by name (`name`, partial match supported) |

#### `scripts` - Ghidra Script Management

Manage and run scripts across all enabled script sources (user scripts in `~/ghidra_scripts` plus bundled/system scripts). Writes and deletes are restricted to the user script directory. Scripts written here appear in Ghidra's Script Manager after clicking Refresh.

| Action | Description |
| ------ | ----------- |
| `list` | List scripts with `name`, `category`, `description`, `runtime`, and `path` (optional `pattern` filter, `user_only`, `offset`/`limit` pagination) |
| `read` | Return the source of a named script (`name`); user scripts first, then any enabled script source; optional `max_bytes` cap |
| `write` | Create or overwrite a user script (`name`, `code`, optional `category`, `description`); prepends `@category`/`@description` metadata automatically; requires `overwrite=true` to replace an existing script |
| `run` | Execute a named script in the current Ghidra context (`name`, optional `args`); runs as an async task when the task manager is available; output is captured and returned |
| `delete` | Delete a user script file (`name`); requires `confirm=true` |

### Function Discovery & Analysis

| Tool | Description |
| ---- | ----------- |
| `get_functions` | List functions with optional pattern filtering and pagination |
| `search_functions_by_name` | Find functions by name pattern |
| `get_function_statistics` | Comprehensive statistics for all functions |
| `analyze_function` | Get detailed function information (signature, variables, etc.) |
| `get_current_function` | Get function at current cursor position |
| `get_function_stack_layout` | Get stack frame layout with variable offsets |
| `get_basic_blocks` | Get basic block information for a function |
| `create_function` | Create/define a function at an address, optionally clearing existing data/code first |
| `disassemble_at` | Disassemble code at an address, optionally clearing existing data/code in the range first |

### Binary Information

| Tool | Description |
| ---- | ----------- |
| `get_imports` | List imported functions/symbols |
| `get_exports` | List exported functions/symbols |
| `get_strings` | List string references with optional filtering |
| `search_strings` | Search strings by pattern |
| `get_segments` | List memory segments |
| `get_namespaces` | List namespaces in the program |
| `get_relocations` | List relocation entries |
| `get_entry_points` | List all binary entry points |

### Data Analysis

| Tool | Description |
| ---- | ----------- |
| `get_data_vars` | List data definitions in the program |
| `get_data_at` | Get hexdump/data at a specific address |
| `create_data_var` | Define data variables at addresses |
| `get_current_address` | Get current cursor address |

### Consolidated Tools

These tools bundle related operations behind a discriminator parameter (e.g., `action`, `target`, `target_type`, or `format`).

#### `get_code` - Code Retrieval Tool

| Parameter | Values | Description |
| --------- | ------ | ----------- |
| `format` | `decompiler`, `disassembly`, `pcode` | Output format |
| `raw` | boolean | Only affects `format: "pcode"` (raw pcode ops vs grouped by basic blocks) |

#### `classes` - Class Operations Tool

| Action | Description |
| ------ | ----------- |
| `list` | List classes with optional pattern filtering and pagination |
| `get_info` | Get detailed class information (methods, fields, vtables, virtual functions) |

#### `xrefs` - Cross-Reference Tool

| Parameter | Description |
| --------- | ----------- |
| `address` | Find all references to/from a specific address |
| `function` | Find all cross-references for a function |
| `include_calls` | Include callers/callees (replaces separate call graph tool) |

#### `struct` - Structure Operations Tool

| Action | Description |
| ------ | ----------- |
| `create` | Create a new structure from C definition or empty |
| `modify` | Modify an existing structure with new C definition |
| `merge` | Merge (overlay) fields from a C definition onto an existing structure without deleting existing fields |
| `set_field` | Set/insert a single field at a specific offset without needing a full C struct (use `field_name` to name it) |
| `name_gap` | Convert undefined bytes at an offset/length into a named `byte[]`-like field (useful for “naming gaps”; uses `field_name`) |
| `auto_create` | Automatically create structure from variable usage patterns |
| `rename_field` | Rename a field within a structure |
| `field_xrefs` | Find cross-references to a specific struct field |
| `search_comments` | Search struct field comments (and optionally names) for a pattern; defaults to `-BAD-` (Ghidra's marker for deleted members) |
| `find_enum_use` | Find all struct fields whose resolved base type is a given enum (unwraps pointers, arrays, and typedefs) |
| `replace_type` | Replace all uses of one struct type with another across the entire program (variables, fields, typedefs) |

#### `rename_symbol` - Symbol Renaming Tool

| Parameter | Values | Description |
| --------- | ------ | ----------- |
| `target_type` | `function`, `data`, `variable` | What kind of symbol to rename |

#### `batch_rename` - Batch Symbol Renaming Tool

Rename multiple symbols in one operation.

#### `comments` - Comment Management Tool

| Action | Description |
| ------ | ----------- |
| `get` | Get comment at an address |
| `set` | Set a comment at an address or on a function |
| `list` | List all comments |
| `remove` | Remove a comment |

#### `variables` - Variable Management Tool

| Action | Description |
| ------ | ----------- |
| `list` | List local variables for a function |
| `rename` | Rename a local variable or a global/data symbol using `scope` |
| `set_type` | Set data type for a local variable |
| `set_prototype` | Set function signature/prototype |

#### `types` - Type Management Tool

| Action | Description |
| ------ | ----------- |
| `list` | List all available data types |
| `get_info` | Get detailed data type information and structure definitions |
| `set` | Set data type at a specific address, including arrays with `array_count` or suffix syntax like `int[16]` |
| `delete` | Delete a data type by name (optionally scoped by `category`) |

#### `bookmarks` - Bookmark Management Tool

| Action | Description |
| ------ | ----------- |
| `list` | List all bookmarks |
| `set` | Set a new bookmark |
| `remove` | Remove a bookmark |

#### `enum` - Enum Data Type Tool

| Action | Description |
| ------ | ----------- |
| `list` | List all enum data types (optional `pattern` filter) |
| `get_info` | Get details of an enum including all named values |
| `create` | Create a new enum with optional `size` (1/2/4/8 bytes) and initial `values` (`"NAME=VALUE,..."`) |
| `add_value` | Add a named value (`value_name`, `value`) to an existing enum |
| `remove_value` | Remove a named value from an existing enum |
| `rename_value` | Rename a value within an enum (`value_name` → `new_name`) |
| `rename` | Rename the enum data type itself |
| `delete` | Delete an enum data type |

Use `category` (e.g. `/MyTypes`) to scope lookups or set the destination for `create`.

#### `equate` - Equate Tool

Equates associate symbolic names with constant integer values used in disassembly.

| Action | Description |
| ------ | ----------- |
| `list` | List all equates (optional `pattern` filter) |
| `get_info` | Get details of a specific equate |
| `create` | Create an equate with a `name` and numeric `value` |
| `rename` | Rename an equate (`name` → `new_name`) |
| `delete` | Delete an equate |

#### `eval_python` - PyGhidra Evaluator Tool

| Parameter | Description |
| --------- | ----------- |
| `script`  | Python 3 code to execute in Ghidra's context. Requires launching Ghidra with `pyghidra.bat` for Python 3 support (or falls back to Jython 2.7). Globals: `currentProgram`, `currentAddress`, `monitor`, `state`. |
| `sync`    | Optional boolean. Default `false` (async — returns a `task_id`, poll with `get_task_status`). Pass `true` for inline result on quick scripts (under ~2s) to skip the task-id round-trip. |

A `ghidra` helper object is pre-injected with common operations:

| Helper | Description |
| ------ | ----------- |
| `ghidra.decompile(id)` | Decompile a function by name or address |
| `ghidra.get_func(id)` | Return a `Function` object by name or address |
| `ghidra.get_program(name)` | Return an open `Program` object by name |
| `ghidra.get_refs_to(addr)` | List all callers of an address |
| `ghidra.set_comment(addr, text, type)` | Set an EOL/PRE/POST/PLATE comment |
| `ghidra.find_struct(name)` | Return a `Structure` data type object (warning: stringifying dumps the entire field table — use `struct_summary`/`struct_fields` for compact output) |
| `ghidra.struct_summary(name)` | Compact summary: `{name, size, field_count, category}` |
| `ghidra.struct_fields(name, prefix=None)` | Slim field list: `[(offset, name, type, size)]` (optional name-prefix filter) |
| `ghidra.read_bytes(addr, length)` | Read memory as a hex string |
| `ghidra.copy_datatype(name, from_prog, to_prog)` | Copy a struct/enum between open programs |
| `ghidra.list_vt_sessions()` | List open Version Tracking sessions: `[{name, src, dst, match_count}]` |
| `ghidra.get_vt_session(idx=0)` | Return a `VTSession` by index |
| `ghidra.get_vt_matches(session, status)` | Return `[{src, dst, status, similarity, confidence}]`; filter by `ACCEPTED`/`REJECTED`/`AVAILABLE` |
| `ghidra.find_addr_in_version(addr, session)` | Find the accepted destination address for a source address across binary versions |
| `ghidra.accept_vt_match(src_addr, session)` | Accept the first available VT match for a source address |

A `dbg` helper object is also pre-injected for dynamic analysis via the Ghidra Debugger. It owns the whole debugger session lifecycle — attach, inspect, control, detach — from MCP, no GUI needed.

| Helper | Description |
| ------ | ----------- |
| `dbg.attach(pid, offer_title=None, mode='default')` | **Start a session**: attach to a running process by PID (defaults to "dbgeng attach" on Windows). `mode='observe'` uses dbgeng's `DEBUG_ATTACH_NONINVASIVE \| DEBUG_ATTACH_NONINVASIVE_NO_SUSPEND` — the target is never stopped, so it's the safe default for read-only live memory/struct work (`reng.explore`/`find_instances`/`label`/`diff*`); verified live against a running game (CPU time kept climbing throughout, confirming no suspend). `mode='default'` is invasive (suspends) and required for breakpoints/stepping/register writes. Call via `eval_python`'s default async execution, not `sync=True` — the subprocess launch and module resolution can take several seconds. Returns `{ok, offer, trace, image_base, modules_ready, armed_breakpoints, mode}` |
| `dbg.list_attach_offers()` | Attach-capable backends available for `dbg.attach` (e.g. "dbgeng attach", gdb/lldb variants) |
| `dbg.status()` | Summary dict: `{connected, trace, snap, thread, has_live_target, control_mode}`. Not connected? `dbg.attach(<pid>)` |
| `dbg.list_sessions()` | `{open_traces, connections, acceptors}` — open traces and active TraceRMI connections |
| `dbg.server_info()` | `{server_started, server_address}` — TraceRMI inbound server state (rarely needed; attach auto-starts it) |
| `dbg.execute(cmd)` | Run a raw dbgeng/WinDbg command and return its output: `k`, `~`, `lm`, `sxd av`, `.lastevent`, `!analyze -v`, `bp …`. The keystone for engine features Ghidra doesn't surface |
| `dbg.py_execute(python)` | Run raw Python in the ghidradbg backend process (`util`, `util.dbg` in scope); stdout captured |
| `dbg.health()` | Long-session resource report: `{snap_count, max_snap, thread_count, module_count, breakpoint_count, mcp_task_count}` |
| `dbg.execute(cmd)` | Run a raw dbgeng/WinDbg command and return its output: `k`, `~`, `lm`, `sxd av`, `.lastevent`, `!analyze -v`, `bp …`. The keystone for engine features Ghidra doesn't surface |
| `dbg.py_execute(python)` | Run raw Python in the ghidradbg backend process (`util`, `util.dbg` in scope); stdout captured |
| `dbg.health()` | Long-session resource report: `{snap_count, max_snap, thread_count, module_count, breakpoint_count, mcp_task_count}` |
| `dbg.cleanup(keep_snaps=None)` | Delete old trace snapshots via `TraceSnapshot.delete()` to compact the `.DBTrace` file (keeps current snap by default) |
| `dbg.detach()` | Clean target disconnect (interrupt → DETACH → close trace → close TraceRMI connection); keeps the debuggee process alive. Captures `last_event`/`event_registers`/`get_stack` *before* tearing the trace down, so calling it reflexively after an unexpected break doesn't lose that data. Returns `{steps, forensics: {last_event, event_registers, stack}}` |
| `dbg.get_threads()` | List all `TraceThread` objects in the active trace |
| `dbg.get_thread()` / `dbg.get_snap()` | Current thread and snapshot index |
| `dbg.get_event_thread()` | The faulting thread that caused the current break: `{tid, name, key, thread}` (`thread` is the raw `TraceThread` for `get_registers(thread=…)`) — not the parked worker `get_thread()` often returns |
| `dbg.list_modules(name_filter=None)` | Loaded modules with runtime base addresses: `[{name, base, length, path}]` — essential for ASLR conversion |
| `dbg.last_event()` | Exception/event that caused the break: `{code, first_chance, thread_id, description, raw}` (code as int, e.g. `0xc0000409`) |
| `dbg.get_registers(thread, frame, snap)` | Register values as `{name: int}` dict |
| `dbg.event_registers()` | Registers of the faulting thread via dbgeng `r` — reliable on a break (avoids trace-register-space staleness) |
| `dbg.refresh_registers()` | Force live register read from target into trace |
| `dbg.write_register(name, value)` | Write a register value (requires RW control mode) |
| `dbg.read_memory(addr, length, snap)` | Read bytes from trace memory as hex string; accepts EITHER static or live address (auto-translated) |
| `dbg.read_bytes(addr, n)` | Read `n` bytes as a Python `bytes` object (refreshes from target by default) |
| `dbg.read_u64/read_u32(addr)` / `dbg.read_ptr(addr)` / `dbg.read_int(addr, size, signed)` | Typed little-endian scalar reads (int) for chasing pointer chains and fields |
| `dbg.refresh_memory(addr, length)` | Force live memory read from target into trace; accepts either address space |
| `dbg.write_memory(addr, hex_bytes)` | Write bytes to live target memory; accepts either address space |
| `dbg.resume()` / `dbg.interrupt()` | Resume or suspend the target |
| `dbg.step_into()` / `dbg.step_over()` / `dbg.step_out()` | Single-step execution |
| `dbg.kill()` | Kill the target process |
| `dbg.list_breakpoints()` | All logical breakpoints: `[{address: '0x...', state, kinds, length, name}]` |
| `dbg.set_breakpoint(addr, length, name, raw=False)` | Logical breakpoint at a static Ghidra address (auto-mapped); returns `{ok, address, state, message}`. `raw=True` issues a dbgeng `bp` on a runtime address — for unmapped/system modules (d3d11.dll, ntdll) not loaded as static programs |
| `dbg.set_raw_breakpoint(rt_addr, kind='e')` | dbgeng `bp` (execute) or `ba` (hardware r/w data) directly on a runtime address, bypassing static mapping; returns `{ok, address, command, output}` |
| `dbg.remove_raw_breakpoint(rt_addr)` | Remove the raw dbgeng breakpoint at a runtime address (pairs with `set_raw_breakpoint`); returns `{ok, address, removed, output}` |
| `dbg.delete_breakpoints(addr)` | Remove all *logical* breakpoints at a static address (also clears program-side `BreakpointMarker` bookmarks); returns `{ok, address, deleted, message}` |
| `dbg.set_exception_filter(code, disposition)` | Control dbgeng exception handling: `break`(sxe)/`second`(sxd)/`notify`(sxn)/`ignore`(sxi). `code` is an int (`0xc0000409`) or filter name (`av`,`sbo`). Returns `{ok, command, output}`. Catch one exception in a storm |
| `dbg.list_exception_filters()` | Current exception/event filter dispositions (dbgeng `sx`) |
| `dbg.ensure_static_mapping()` | Add (or update) the trace ↔ program static mapping required for breakpoints to resolve; called automatically by `set_breakpoint` |
| `dbg.get_stack(thread, snap, walk=True)` | Backtrace. Trace-recorded frames are `{level, pc}`; with `walk` and a live session returns the full parsed dbgeng `k` walk `[{level, stack_ptr, ret_addr, location, module, symbol}]` |

**Address spaces.** `dbg.set_breakpoint` / `delete_breakpoints` take static Ghidra addresses (auto-mapped to live via the trace). The memory methods (`read_memory`, `write_memory`, `refresh_memory`) accept *either* a static or a live address and translate automatically when the value falls in `currentProgram`'s image range. If `read_memory` returns all zeros for a known-mapped region, the page is "cold" — call `refresh_memory(addr, length)` first.

**Multi-version projects.** Program↔module matching defaults to an exact file-name match, so a wrong-version binary is never bound silently. When a program is loaded under a name that differs from the live module (e.g. program `SkyrimSE.1170.exe` vs live module `SkyrimSE.exe`), bind it explicitly with `dbg.use_image("SkyrimSE.exe")` or `reng.use_image("SkyrimSE.exe")` (pass `None` to reset). The override applies to `reng.image_base()`, `ensure_static_mapping`, and memory address translation.

**Raw engine passthrough.** `dbg.execute()` runs any dbgeng/WinDbg command and returns its text output. It is the keystone behind `last_event`, `set_exception_filter`, raw breakpoints, and the `get_stack` backtrace fallback — and is available directly for anything the structured helpers don't cover (`!analyze -v`, `dt`, `u`, `!teb`, etc.).

A `reng` helper object is pre-injected for reverse-engineering workflows. Works with or without a live debugger session; some methods require dynamic state, others operate purely on static analysis.

**ASLR address conversion:**

| Helper | Description |
| ------ | ----------- |
| `reng.image_base()` | Runtime image base of `currentProgram` (canonical, from trace module manager; falls back to thread-name parsing if modules aren't enumerated yet) |
| `reng.to_rt(static_addr)` | Convert static Ghidra address → live runtime address |
| `reng.to_static(rt_addr)` | Convert live runtime address → static Ghidra address |
| `reng.use_image(name)` / `dbg.use_image(name)` | Bind `currentProgram` to a differently-named live module (multi-version projects); `None` resets to exact same-name matching |

**RTTI inspection (MSVC x64):**

| Helper | Description |
| ------ | ----------- |
| `reng.rtti(rt_obj_ptr)` | Decode the C++ class name of a live object pointer (reads `vtable[-8]` → `RTTICompleteObjectLocator` → `TypeDescriptor`) |
| `reng.class_hierarchy(rt_ptr)` | Full inheritance chain: `[{class, offset, index}]` ordered base → derived |
| `reng.vtable_methods(rt_ptr, max=128)` | List vtable slots: `[{slot, rt, static, name, named}]` — `name` comes from Ghidra analysis |
| `reng.scan_vtables(prog=None)` | Scan `.rdata` for all RTTI vtables; returns `{vtable_static_addr: class_name}` (cached per program) |
| `reng.rename_vfuncs(vtable_map=None, dry_run=False)` | Bulk-rename `FUN_*` into `ClassName::vfunc_N` using `scan_vtables` map |

**ReClass.NET-style struct exploration** (backed by Ghidra's `DataTypeManager` — no parallel store; reads from and writes to the existing DTM):

| Helper | Description |
| ------ | ----------- |
| `reng.explore(rt_addr, size=256)` | Field table at a live address; inherited fields tagged `(from ClassName)`; auto-detects vtable / fn-ptrs / sub-object pointers / nulls / floats |
| `reng.follow(rt_addr, offset)` | Dereference the pointer at `[rt_addr+offset]` and `explore()` the sub-object |
| `reng.tree(rt_addr, depth=2, max_ptrs=8, size=128)` | Recursive exploration that follows pointer fields |
| `reng.diff(rt_addr1, rt_addr2, size=256, threshold=0)` | Compare two instances; returns differing 8-byte slots — the "damage one Actor, diff to find health" technique |
| `reng.snapshot_state(rt_addr, size=256, label=None)` | Capture bytes now for later temporal diffing — the single-singleton complement to `diff()` |
| `reng.diff_snapshot(rt_addr, size=256, label=None, threshold=0)` | Diff current memory against a `snapshot_state()` capture — freeze a singleton, trigger an action in-game, see what changed |
| `reng.as_array(rt_addr, offset, count, type_str='f32')` | Read N consecutive typed values (`f32`/`u32`/`ptr`/...) |
| `reng.as_known(rt_addr, offset, struct_name)` | Read an inline embedded sub-struct using a Ghidra DataType name (e.g. `NiPoint3` for an embedded XYZ) |
| `reng.read_struct(rt_addr, {fname: (off, type)})` | Read named fields from an explicit field map |
| `reng.find_type_at(rt_addr, offset, size=8)` | Cross-reference a single field against Ghidra's view (function? known vtable? small int? float?) |

**Struct authoring (C++ inheritance-aware):**

| Helper | Description |
| ------ | ----------- |
| `reng.define_class(name, own_fields, base_class=None, total_size=None, category='/')` | Create/update a struct with proper inheritance — embeds `base_class` at offset 0 so the decompiler shows `this->BaseClass_base.field` |
| `reng.build_hierarchy(rt_ptr)` | Auto-build the full RTTI inheritance chain in the DTM (e.g. `TESForm → TESObjectREFR → Actor`); preserves existing named fields |
| `reng.define_struct(name, fields, category='/')` | Flat struct (no inheritance) — for simple/value types; call with `fields={}` to inspect current definition |
| `reng.patch_struct(name, fields, force=False)` | Targeted field update for partially RE'd projects: overwrites provisional names (`unk*`/`pad*`/`gap*`/`field_*`) freely; `force=True` to overwrite established names |
| `reng.is_provisional(field_name)` | True if name matches `reng.PROVISIONAL_PREFIXES` (configurable per project) |
| `reng.apply_struct(addr, struct_name, is_runtime=False)` | Apply a Ghidra DataType to an address in the Listing view |
| `reng.label(rt_addr, fields, struct_name=None, force=False)` | One-call commit+apply+verify: patches/creates the struct, applies it, and returns the refreshed `explore()` view — collapses the usual 3-round-trip fix loop into one |
| `reng.rename_function(static_addr, new_name, namespace=None)` | Rename a function (USER_DEFINED source; survives re-analysis); optional class namespace |

For managing script files, use the `scripts` MCP tool (list/read/write/run/delete) rather than the analysis prelude.

Typical dynamic-analysis workflow (all via `eval_python` + the `dbg` helper):
1. `dbg.attach(<pid>)` — attach to a running process (`dbg.list_attach_offers()` lists backends); creates the session. Pass `mode='observe'` for read-only work (live struct/singleton exploration) — the target is never suspended, so it's safe against a real/HMD session; the default `mode='default'` is invasive and only needed for breakpoints/stepping/register writes.
2. `dbg.status()` — confirm `connected: True`
3. `dbg.get_registers()` / `dbg.read_memory(addr, n)` / `dbg.set_breakpoint(addr)` to inspect and instrument (breakpoints/writes require `mode='default'`)
4. `dbg.resume()` / `dbg.interrupt()` to control execution; `dbg.detach()` when done — its return value includes captured `last_event`/registers/stack, taken before the trace is closed

To locate an object instance to inspect, use `reng.find_instances(class_or_vtable)`. For read-only live struct/singleton work end to end: `dbg.attach(pid, mode='observe')` → `reng.explore(addr)`/`find_instances`/`snapshot_state`+`diff_snapshot` → `reng.label(addr, fields)` to commit corrections → `dbg.detach()`.

#### `eval_python` caveats

- **Transactions:** each `eval_python` call runs inside one Ghidra transaction. The
  built-in `reng`/`ghidra` write helpers handle this correctly, but in hand-written
  scripts never end a transaction with `commit=False` — a nested abort rolls back the
  *entire* eval, silently reverting every other write in the run. Use one always-committed
  transaction. You also cannot `File → Save` from inside an eval (the active transaction
  holds the lock); call the `save_program` tool afterward instead (or save from the GUI).
- **Live VR targets:** the SteamVR compositor terminates a process that stops submitting
  frames, so any debugger break or long frozen-memory scan can kill the game. Capture fast
  then detach (`dbg.snapshot(addr, len, then='detach')`), or run under the SteamVR **null
  driver** to suspend indefinitely — note the null driver provides an HMD but no
  controllers, so controller-state structs won't populate unless controllers are emulated.

### Search Tools

| Tool | Description |
| ----- | ----------- |
| `search_bytes` | Search for byte patterns in memory |

### Async Task Management

Long-running operations (decompilation, structure analysis, field xrefs) execute asynchronously:

| Tool | Description |
| ---- | ----------- |
| `get_task_status` | Check status and retrieve results of async tasks |
| `cancel_task` | Cancel a running async task |
| `list_tasks` | List all pending/running/completed tasks |

## MCP Resources

GhidrAssistMCP exposes 6 static resources that can be read by MCP clients:

| Resource URI | Description |
| ------------ | ----------- |
| `ghidra://program/{name}/info` | Basic program information |
| `ghidra://program/{name}/functions` | List of all functions |
| `ghidra://program/{name}/strings` | String references |
| `ghidra://program/{name}/imports` | Imported symbols |
| `ghidra://program/{name}/exports` | Exported symbols |
| `ghidra://program/{name}/segments` | Memory segments |

## MCP Prompts

Pre-built prompts for common analysis tasks:

| Prompt | Description |
| ------ | ----------- |
| `analyze_function` | Comprehensive function analysis prompt |
| `identify_vulnerability` | Security vulnerability identification |
| `document_function` | Generate function documentation |
| `trace_data_flow` | Data flow analysis prompt |
| `trace_network_data` | Trace network send/recv call stacks for protocol analysis and network vulnerability identification |
| `compare_functions` | Diff two functions for similarity analysis |
| `reverse_engineer_struct` | Recover structure definitions from usage patterns |

## Usage Examples

### Basic Program Information

```json
{
  "method": "tools/call",
  "params": {
    "name": "get_binary_info"
  }
}
```

### List Functions with Pattern Filtering

```json
{
  "method": "tools/call",
  "params": {
    "name": "get_functions",
    "arguments": {
      "pattern": "init",
      "case_sensitive": false,
      "limit": 50
    }
  }
}
```

### Decompile Function (`get_code`)

```json
{
  "method": "tools/call",
  "params": {
    "name": "get_code",
    "arguments": {
      "function": "main",
      "format": "decompiler"
    }
  }
}
```

### Get Class Information (Action-Based)

```json
{
  "method": "tools/call",
  "params": {
    "name": "classes",
    "arguments": {
      "action": "get_info",
      "class_name": "MyClass"
    }
  }
}
```

### Search Classes (Action-Based)

```json
{
  "method": "tools/call",
  "params": {
    "name": "classes",
    "arguments": {
      "action": "list",
      "pattern": "Socket",
      "case_sensitive": false
    }
  }
}
```

### Auto-Create Structure (Action-Based)

```json
{
  "method": "tools/call",
  "params": {
    "name": "struct",
    "arguments": {
      "action": "auto_create",
      "function_identifier": "0x00401000",
      "variable_name": "ctx"
    }
  }
}
```

### Find Struct Field Cross-References (Action-Based)

```json
{
  "method": "tools/call",
  "params": {
    "name": "struct",
    "arguments": {
      "action": "field_xrefs",
      "structure_name": "Host",
      "field_name": "port"
    }
  }
}
```

### Delete a Data Type

If multiple types share the same name across categories, pass `category` (or pass a full path in `name` starting with `/`).

```json
{
  "method": "tools/call",
  "params": {
    "name": "types",
    "arguments": {
      "action": "delete",
      "name": "MyStruct",
      "category": "/mytypes"
    }
  }
}
```

### Set an Array Data Type

```json
{
  "method": "tools/call",
  "params": {
    "name": "types",
    "arguments": {
      "action": "set",
      "address": "0x00402000",
      "data_type": "int[16]"
    }
  }
}
```

Equivalent form:

```json
{
  "method": "tools/call",
  "params": {
    "name": "types",
    "arguments": {
      "action": "set",
      "address": "0x00402000",
      "data_type": "int",
      "array_count": 16
    }
  }
}
```

### Create a Function

```json
{
  "method": "tools/call",
  "params": {
    "name": "create_function",
    "arguments": {
      "address": "0x00401000",
      "name": "mainWndProc"
    }
  }
}
```

For overlays or mixed code/data regions where Ghidra defined code as data, clear the existing code unit or an explicit range first:

```json
{
  "method": "tools/call",
  "params": {
    "name": "create_function",
    "arguments": {
      "address": "0x80012340",
      "name": "ovl_init",
      "clear_existing": true,
      "clear_length": 256
    }
  }
}
```

### Rename Function (Action-Based)

```json
{
  "method": "tools/call",
  "params": {
    "name": "rename_symbol",
    "arguments": {
      "action": "function",
      "address": "0x00401000",
      "new_name": "decrypt_buffer"
    }
  }
}
```

### Multi-Program Support

When working with multiple open programs, first list them:

```json
{
  "method": "tools/call",
  "params": {
    "name": "list_binaries"
  }
}
```

Then specify which program to target using `program_name`. When multiple programs share the same filename, use the `Project Path` shown by `list_binaries`:

```json
{
  "method": "tools/call",
  "params": {
    "name": "get_functions",
    "arguments": {
      "program_name": "/project/folder/target_binary.exe",
      "limit": 10
    }
  }
}
```

## Multi-Window Support & Active Context Awareness

GhidrAssistMCP uses a singleton architecture that enables seamless operation across multiple CodeBrowser windows:

### How It Works

1. **Single Shared Server**: One MCP server (port 8080) serves all CodeBrowser windows
2. **Focus Tracking**: Automatically detects which CodeBrowser window is currently active
3. **Context Hints**: All tool responses include context information to help AI understand which binary is in focus

### Context Information in Responses

Every tool response includes a context header:

```plaintext
[Context] Operating on: malware.exe | Active window: malware.exe

<tool response content>
```

or when targeting a different program:

```plaintext
[Context] Operating on: lib.so | Active window: main.exe | Total open programs: 3

<tool response content>
```

### Benefits for AI Assistants

- **Smart Defaults**: When no `program_name` is specified, tools automatically use the program from the active window
- **Context Awareness**: AI knows which binary the user is currently viewing
- **Prevents Confusion**: Clear indication when operating on a different binary than what's in the active window
- **Multi-tasking**: Work with multiple binaries without constantly specifying which one to target

## Architecture

### Core Components

```plaintext
GhidrAssistMCP/
├── GhidrAssistMCPManager     # Singleton coordinator for multi-window support
│   ├── Tracks all CodeBrowser windows
│   ├── Manages focus tracking
│   └── Owns shared server and backend
├── GhidrAssistMCPPlugin      # Plugin instance (one per CodeBrowser window)
│   └── Registers with singleton manager
├── GhidrAssistMCPServer      # HTTP MCP server (Streamable HTTP)
│   └── Single shared instance on port 8080
├── GhidrAssistMCPBackend     # Tool management and execution
│   ├── Tool registry with enable/disable states
│   ├── Result caching system
│   ├── Async task management
│   └── Resource and prompt registries
├── GhidrAssistMCPProvider    # UI component provider
│   └── First registered instance provides UI
├── cache/                    # Caching infrastructure
│   ├── McpCache.java
│   └── CacheEntry.java
├── tasks/                    # Async task management
│   ├── McpTaskManager.java
│   └── McpTask.java
├── resources/                # MCP Resources (6 total)
│   ├── ProgramInfoResource.java
│   ├── FunctionListResource.java
│   ├── StringsResource.java
│   ├── ImportsResource.java
│   ├── ExportsResource.java
│   └── SegmentsResource.java
├── prompts/                  # MCP Prompts (7 total)
│   ├── AnalyzeFunctionPrompt.java
│   ├── IdentifyVulnerabilityPrompt.java
│   ├── DocumentFunctionPrompt.java
│   ├── TraceDataFlowPrompt.java
│   ├── TraceNetworkDataPrompt.java
│   ├── CompareFunctionsPrompt.java
│   └── ReverseEngineerStructPrompt.java
└── tools/                    # MCP Tools (49 total)
    ├── Consolidated action-based tools
    ├── Analysis tools
    ├── Modification tools
    └── Navigation tools
```

### Tool Design Patterns

**Consolidated Tools**: Related operations are consolidated into single tools with a discriminator parameter:

- `get_code`: `format: decompiler|disassembly|pcode`
- `classes`: `action: list|get_info`
- `struct`: `action: create|modify|merge|set_field|name_gap|auto_create|rename_field|field_xrefs`
- `rename_symbol`: `target_type: function|data|variable`
- `comments`: `action: get|set|list|remove`
- `variables`: `action: list|rename|set_type|set_prototype` with `scope: auto|local|global` for rename
- `types`: `action: list|get|set|create_struct|create_enum|create_typedef|delete`
- `bookmarks`: `action: list|set|remove`
- `xrefs`: `address|function` with `include_calls` parameter
- `analysis_options`: `action: list|set|reset|save_preset|apply_preset|list_presets|delete_preset`
- `analysis_control`: `action: status|cancel`
- `project_files`: `action: list|delete`
- `scripts`: `action: list|read|write|delete|run`

**Tool Interface Methods**:

- `isReadOnly()`: Indicates if tool modifies program state
- `isLongRunning()`: Triggers async execution with task management
- `isCacheable()`: Enables result caching for repeated queries
- `isDestructive()`: Marks potentially dangerous operations
- `isIdempotent()`: Indicates if repeated calls produce same result

### MCP Protocol Implementation

- **Transports**:
  - Streamable HTTP
- **Endpoints**:
  - `GET /mcp` - Receive Streamable HTTP events
  - `POST /mcp` - Initialize Streamable HTTP session
  - `DELETE /mcp` - Terminate Streamable HTTP session
- **Capabilities**: Tools, Resources, Prompts

## Development

### Project Structure

```plaintext
src/main/java/ghidrassistmcp/
├── GhidrAssistMCPPlugin.java      # Main plugin class
├── GhidrAssistMCPManager.java     # Singleton coordinator
├── GhidrAssistMCPProvider.java    # UI provider with tabs
├── GhidrAssistMCPServer.java      # MCP server implementation
├── GhidrAssistMCPBackend.java     # Backend tool/resource/prompt management
├── McpBackend.java                # Backend interface
├── McpTool.java                   # Tool interface
├── McpEventListener.java          # Event notification interface
├── cache/                         # Caching system
├── tasks/                         # Async task system
├── resources/                     # MCP resources
├── prompts/                       # MCP prompts
└── tools/                         # Tool implementations
```

### Adding New Tools

1. **Implement McpTool interface**:

   ```java
   public class MyCustomTool implements McpTool {
       @Override
       public String getName() { return "my_custom_tool"; }

       @Override
       public String getDescription() { return "Description"; }

       @Override
       public boolean isReadOnly() { return true; }

       @Override
       public boolean isLongRunning() { return false; }

       @Override
       public boolean isCacheable() { return true; }

       @Override
       public McpSchema.JsonSchema getInputSchema() { /* ... */ }

       @Override
       public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
           // Implementation
       }
   }
   ```

2. **Register in backend**:

   ```java
   // In GhidrAssistMCPBackend constructor
   registerTool(new MyCustomTool());
   ```

### Build Commands

```bash
# Clean build
gradle clean

# Build extension zip (written to dist/)
gradle buildExtension

# Install (extract) extension into the Ghidra user Extensions directory
gradle installExtension

# Uninstall (delete extracted directory from the Ghidra user Extensions directory)
gradle uninstallExtension

# Build/install with specific Ghidra path (required if GHIDRA_INSTALL_DIR isn't set)
gradle -PGHIDRA_INSTALL_DIR=/path/to/ghidra installExtension

# Debug build
gradle buildExtension --debug
```

### Dependencies

- **MCP SDK**: `io.modelcontextprotocol.sdk:mcp-core:1.1.3` / `mcp-json-jackson2:1.1.3`
- **Jetty Server**: `11.0.20` (Streamable HTTP transport)
- **Jackson**: `2.18.3` (JSON processing)
- **Ghidra API**: Bundled with Ghidra installation

## Logging

### UI Logging

The **Log** tab provides real-time monitoring:

- **Session Events**: Server start/stop, program changes
- **Tool Requests**: `REQ: tool_name {parameters...}`
- **Tool Responses**: `RES: tool_name {response...}`
- **Error Messages**: Failed operations and diagnostics
- **Cache Hits**: When cached results are returned

### Console Logging

Detailed logging in Ghidra's console:

- Tool registration and initialization
- MCP server lifecycle events
- Async task execution and completion
- Cache statistics
- Database transaction operations
- Error stack traces and debugging information

## Troubleshooting

### Common Issues

#### Server Won't Start

- Check if port 8080 is available
- Verify Ghidra installation path
- Examine console logs for errors

#### Tools Not Appearing

- Ensure plugin is enabled
- Check Configuration tab for tool status
- Verify backend initialization in logs

#### MCP Client Connection Issues

- Confirm server is running (check GhidrAssistMCP window)
- Test connection: `curl -X POST http://localhost:8080/mcp`
- Check firewall settings

#### Tool Execution Failures

- Verify program is loaded in Ghidra
- Check tool parameters are correct
- Review error messages in Log tab

#### Async Task Issues

- Use `get_task_status` to check task state
- Use `list_tasks` to see all tasks
- Use `cancel_task` if a task is stuck

### Debug Mode

Enable debug logging by adding to Ghidra startup:

```bash
-Dlog4j.logger.ghidrassistmcp=DEBUG
```

## Contributing

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature-name`
3. **Make your changes** with proper tests
4. **Follow code style**: Use existing patterns and conventions
5. **Submit a pull request** with detailed description

### Code Standards

- **Java 21+ features** where appropriate
- **Proper exception handling** with meaningful messages
- **Transaction safety** for all database operations
- **Thread safety** for UI operations
- **Comprehensive documentation** for public APIs
- **Action-based consolidation** for related tool operations

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **NSA/Ghidra Team** for the excellent reverse engineering platform
- **Anthropic** for the Model Context Protocol specification

---

**Questions or Issues?**

Please open an issue on the project repository for bug reports, feature requests, or questions about usage and development.
