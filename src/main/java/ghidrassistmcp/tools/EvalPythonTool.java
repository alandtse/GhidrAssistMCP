/*
 * MCP tool for evaluating arbitrary Python 3 code via GhidraScript (PyGhidra).
 */
package ghidrassistmcp.tools;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;
import java.util.Map;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.app.script.ScriptControls;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Tool to execute arbitrary Python code.
 * Requires pyghidra.bat (Python 3) or falls back to Jython 2.7.
 */
public class EvalPythonTool implements McpTool {

    private static final String PRELUDE = 
        "import ghidra.app.decompiler.DecompInterface as DecompInterface\n" +
        "import ghidra.util.task.TaskMonitor as TaskMonitor\n" +
        "import ghidra.program.model.listing.CommentType as CommentType\n" +
        "import ghidra.program.model.symbol.SourceType as SourceType\n" +
        "try:\n" +
        "    from ghidra.feature.vt.api.main import VTSession, VTMatchInfo\n" +
        "except: pass\n" +
        "class GhidraHelpers:\n" +
        "    def get_program(self, name):\n" +
        "        try:\n" +
        "            from ghidra.app.services import ProgramManager\n" +
        "            pm = state.getTool().getService(ProgramManager)\n" +
        "            for p in pm.getAllOpenPrograms():\n" +
        "                if p.getName() == name: return p\n" +
        "        except: pass\n" +
        "        return None\n" +
        "    def _iter_all_tools(self):\n" +
        "        '''Yield every running PluginTool across all workspaces (includes VT tool windows).'''\n" +
        "        seen = set()\n" +
        "        try:\n" +
        "            proj = state.getProject()\n" +
        "            if proj:\n" +
        "                for ws in proj.getToolManager().getWorkspaces():\n" +
        "                    for t in ws.getTools():\n" +
        "                        if id(t) not in seen:\n" +
        "                            seen.add(id(t)); yield t\n" +
        "        except: pass\n" +
        "    def get_vt_sessions(self):\n" +
        "        '''Return all open VTSessions found across all running Ghidra tools.'''\n" +
        "        sessions = []\n" +
        "        seen = set()\n" +
        "        for tool in self._iter_all_tools():\n" +
        "            # Approach 1: ask for VTController service directly\n" +
        "            try:\n" +
        "                from ghidra.feature.vt.gui.plugin import VTController\n" +
        "                ctrl = tool.getService(VTController)\n" +
        "                if ctrl:\n" +
        "                    sess = ctrl.getSession()\n" +
        "                    if sess is not None and id(sess) not in seen:\n" +
        "                        seen.add(id(sess)); sessions.append(sess)\n" +
        "                    continue\n" +
        "            except: pass\n" +
        "            # Approach 2: scan managed plugins for one that exposes getSession()\n" +
        "            try:\n" +
        "                for plugin in tool.getManagedPlugins():\n" +
        "                    cname = plugin.getClass().getSimpleName()\n" +
        "                    if 'VT' in cname or 'VersionTracking' in cname:\n" +
        "                        try:\n" +
        "                            sess = plugin.getSession()\n" +
        "                            if sess is not None and id(sess) not in seen:\n" +
        "                                seen.add(id(sess)); sessions.append(sess)\n" +
        "                        except: pass\n" +
        "                        try:\n" +
        "                            sess = plugin.getController().getSession()\n" +
        "                            if sess is not None and id(sess) not in seen:\n" +
        "                                seen.add(id(sess)); sessions.append(sess)\n" +
        "                        except: pass\n" +
        "            except: pass\n" +
        "        return sessions\n" +
        "    def get_vt_session(self, idx=0):\n" +
        "        sessions = self.get_vt_sessions()\n" +
        "        return sessions[idx] if len(sessions) > idx else None\n" +
        "    def copy_datatype(self, name, from_prog, to_prog):\n" +
        "        try:\n" +
        "            from ghidra.program.model.data import DataTypeConflictHandler\n" +
        "            dt = None\n" +
        "            for d in from_prog.getDataTypeManager().getAllDataTypes():\n" +
        "                if d.getName() == name:\n" +
        "                    dt = d\n" +
        "                    break\n" +
        "            if dt:\n" +
        "                to_prog.getDataTypeManager().addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER)\n" +
        "                return True\n" +
        "        except: pass\n" +
        "        return False\n" +
        "    def get_addr(self, s):\n" +
        "        if hasattr(s, 'getAddress'): return s.getAddress()\n" +
        "        return currentProgram.getAddressFactory().getAddress(str(s))\n" +
        "    def get_func(self, id):\n" +
        "        fm = currentProgram.getFunctionManager()\n" +
        "        try: \n" +
        "            a = self.get_addr(id)\n" +
        "            if a: return fm.getFunctionAt(a)\n" +
        "        except: pass\n" +
        "        for f in fm.getFunctions(True):\n" +
        "            if f.getName() == id: return f\n" +
        "        return None\n" +
        "    def decompile(self, id):\n" +
        "        f = self.get_func(id)\n" +
        "        if not f: return 'Function not found'\n" +
        "        di = DecompInterface()\n" +
        "        di.openProgram(currentProgram)\n" +
        "        res = di.decompileFunction(f, 30, monitor)\n" +
        "        ret = res.getDecompiledFunction().getC() if res.isValid() else res.getErrorMessage()\n" +
        "        di.dispose()\n" +
        "        return ret\n" +
        "    def get_refs_to(self, addr):\n" +
        "        rm = currentProgram.getReferenceManager()\n" +
        "        return [r.getFromAddress().toString() for r in rm.getReferencesTo(self.get_addr(addr))]\n" +
        "    def set_comment(self, addr, text, type='eol'):\n" +
        "        ct = {'eol': CommentType.EOL, 'pre': CommentType.PRE, 'post': CommentType.POST, 'plate': CommentType.PLATE}.get(type, CommentType.EOL)\n" +
        "        currentProgram.getListing().setComment(self.get_addr(addr), ct, text)\n" +
        "    def find_struct(self, name):\n" +
        "        for dt in currentProgram.getDataTypeManager().getAllDataTypes():\n" +
        "            if dt.getName() == name and 'Structure' in type(dt).__name__: return dt\n" +
        "        return None\n" +
        "    def read_bytes(self, addr, length):\n" +
        "        try:\n" +
        "            b = currentProgram.getMemory().getBytes(self.get_addr(addr), length)\n" +
        "            return ''.join(['%02x' % (x & 0xff) for x in b])\n" +
        "        except: return 'Error reading bytes'\n" +
        "    def get_vt_matches(self, session=None, status=None):\n" +
        "        '''Return list of {src, dst, status, similarity, confidence} dicts.\n" +
        "        status: None=all, or one of ACCEPTED/REJECTED/AVAILABLE to filter.'''\n" +
        "        if session is None: session = self.get_vt_session()\n" +
        "        if not session: return []\n" +
        "        results = []\n" +
        "        for ms in session.getMatchSets():\n" +
        "            for m in ms.getMatches():\n" +
        "                assoc = m.getAssociation()\n" +
        "                s = assoc.getStatus().name()\n" +
        "                if status and s != status: continue\n" +
        "                try: sim = m.getSimilarityScore().getScore()\n" +
        "                except: sim = 0.0\n" +
        "                try: conf = m.getConfidenceScore().getScore()\n" +
        "                except: conf = 0.0\n" +
        "                results.append({'src': str(assoc.getSourceAddress()), 'dst': str(assoc.getDestinationAddress()), 'status': s, 'similarity': sim, 'confidence': conf})\n" +
        "        return results\n" +
        "    def find_addr_in_version(self, addr, session=None):\n" +
        "        '''Find the ACCEPTED destination address matching a source address in a VT session.\n" +
        "        Returns the destination address string, or None if no accepted match found.'''\n" +
        "        if session is None: session = self.get_vt_session()\n" +
        "        if not session: return None\n" +
        "        src = self.get_addr(addr)\n" +
        "        for ms in session.getMatchSets():\n" +
        "            for m in ms.getMatches():\n" +
        "                assoc = m.getAssociation()\n" +
        "                if assoc.getStatus().name() == 'ACCEPTED' and assoc.getSourceAddress() == src:\n" +
        "                    return str(assoc.getDestinationAddress())\n" +
        "        return None\n" +
        "    def accept_vt_match(self, src_addr, session=None):\n" +
        "        '''Accept the first AVAILABLE match for src_addr in the VT session.\n" +
        "        Returns the destination address string, or None if nothing to accept.'''\n" +
        "        if session is None: session = self.get_vt_session()\n" +
        "        if not session: return None\n" +
        "        src = self.get_addr(src_addr)\n" +
        "        for ms in session.getMatchSets():\n" +
        "            for m in ms.getMatches():\n" +
        "                assoc = m.getAssociation()\n" +
        "                if assoc.getSourceAddress() == src and assoc.getStatus().name() == 'AVAILABLE':\n" +
        "                    try:\n" +
        "                        session.updateAssociationStatus(assoc, assoc.getStatus().ACCEPTED)\n" +
        "                        return str(assoc.getDestinationAddress())\n" +
        "                    except Exception as e: print('accept error: ' + str(e))\n" +
        "        return None\n" +
        "    def list_vt_sessions(self):\n" +
        "        '''Return a list of dicts describing open VT sessions: {name, src, dst, match_count}.'''\n" +
        "        result = []\n" +
        "        for sess in self.get_vt_sessions():\n" +
        "            try:\n" +
        "                count = sum(ms.getMatchCount() for ms in sess.getMatchSets())\n" +
        "                result.append({'name': sess.getName(), 'src': sess.getSourceProgram().getName(), 'dst': sess.getDestinationProgram().getName(), 'match_count': count})\n" +
        "            except Exception as e: result.append({'error': str(e)})\n" +
        "        return result\n" +
        "ghidra = GhidraHelpers()\n\n" +
        // ── Debugger helpers ──────────────────────────────────────────────────────────
        // Injected as `dbg`. Requires Ghidra Debugger plugin loaded and an active
        // TraceRMI session. All methods return graceful error strings/dicts on failure.
        //
        // Services accessed (ghidra.app.services.*):
        //   DebuggerTraceManagerService  → trace/thread/snap lifecycle
        //   DebuggerTargetService        → live Target proxy for actions
        //   DebuggerLogicalBreakpointService → logical breakpoint management
        //   DebuggerControlService       → ControlMode queries, StateEditor for writes
        //
        // Execution control routes through Target.collectActions(ActionName, ctx, policy)
        // → ActionEntry.invoke(prompt=False), mirroring FlatDebuggerAPI.doThreadAction.
        "class DebuggerHelpers:\n" +
        "    '''Debugger access. Call dbg.status() first to confirm a session is active.\n" +
        "    Object graph: Trace → TraceThread → TraceMemoryRegisterSpace → RegisterValue\n" +
        "                  Trace → TraceMemoryManager → getBytes(snap, addr, buf)\n" +
        "    Snaps are integer time-points; use dbg.get_snap() for the current one.\n" +
        "    Addresses: pass hex-string ('0x1234') or int; internal conversion via trace.getBaseAddressFactory().\n" +
        "    '''\n" +
        "    def _tool(self):\n" +
        "        return state.getTool()\n" +
        "    def _svc(self, cls_fqn):\n" +
        "        try:\n" +
        "            parts = cls_fqn.rsplit('.', 1)\n" +
        "            import importlib\n" +
        "            mod = importlib.import_module(parts[0])\n" +
        "            cls = getattr(mod, parts[1])\n" +
        "            return self._tool().getService(cls)\n" +
        "        except: return None\n" +
        "    def get_trace_manager(self):\n" +
        "        '''DebuggerTraceManagerService — trace/thread lifecycle.'''\n" +
        "        return self._svc('ghidra.app.services.DebuggerTraceManagerService')\n" +
        "    def get_target_service(self):\n" +
        "        '''DebuggerTargetService — get live Target for action dispatch.'''\n" +
        "        return self._svc('ghidra.app.services.DebuggerTargetService')\n" +
        "    def get_bp_service(self):\n" +
        "        '''DebuggerLogicalBreakpointService — logical breakpoint CRUD.'''\n" +
        "        return self._svc('ghidra.app.services.DebuggerLogicalBreakpointService')\n" +
        "    def get_trace(self):\n" +
        "        '''Active Trace object, or None if no debugger session.'''\n" +
        "        tm = self.get_trace_manager()\n" +
        "        return tm.getCurrentTrace() if tm else None\n" +
        "    def get_thread(self):\n" +
        "        '''Currently focused TraceThread, or None.'''\n" +
        "        tm = self.get_trace_manager()\n" +
        "        return tm.getCurrentThread() if tm else None\n" +
        "    def get_snap(self):\n" +
        "        '''Current snapshot index (long). Returns -1 if no session.'''\n" +
        "        tm = self.get_trace_manager()\n" +
        "        return tm.getCurrentSnap() if tm else -1\n" +
        "    def get_threads(self):\n" +
        "        '''List all TraceThread objects in the active trace.'''\n" +
        "        trace = self.get_trace()\n" +
        "        if not trace: return []\n" +
        "        return list(trace.getThreadManager().getAllThreads())\n" +
        "    def get_registers(self, thread=None, frame=0, snap=None):\n" +
        "        '''Register values as {name: int} dict.\n" +
        "        Reads from trace memory register space (no live refresh).\n" +
        "        For live values call dbg.refresh_registers() first.'''\n" +
        "        try:\n" +
        "            if thread is None: thread = self.get_thread()\n" +
        "            if snap is None: snap = self.get_snap()\n" +
        "            if thread is None or snap < 0: return {'error': 'no active thread/snap'}\n" +
        "            space = thread.getTrace().getMemoryManager().getMemoryRegisterSpace(thread, frame, False)\n" +
        "            if not space: return {'error': 'no register space for thread'}\n" +
        "            result = {}\n" +
        "            for reg in thread.getTrace().getBaseLanguage().getRegisters():\n" +
        "                if reg.isBaseRegister():\n" +
        "                    try:\n" +
        "                        val = space.getValue(snap, reg)\n" +
        "                        if val: result[reg.getName()] = val.getUnsignedValue().longValue()\n" +
        "                    except: pass\n" +
        "            return result\n" +
        "        except Exception as e: return {'error': str(e)}\n" +
        "    def refresh_registers(self, thread=None, frame=0, snap=None):\n" +
        "        '''Ask the live target to refresh register state into the trace (requires live session).'''\n" +
        "        try:\n" +
        "            if thread is None: thread = self.get_thread()\n" +
        "            trace = thread.getTrace()\n" +
        "            target = self.get_target_service().getTarget(trace)\n" +
        "            if not target: return 'no target'\n" +
        "            platform = trace.getPlatformManager().getCurrentPlatform()\n" +
        "            if snap is None: snap = self.get_snap()\n" +
        "            regs = set(trace.getBaseLanguage().getRegisters())\n" +
        "            target.readRegisters(platform, thread, frame, regs)\n" +
        "            return 'ok'\n" +
        "        except Exception as e: return 'error: ' + str(e)\n" +
        "    def read_memory(self, addr, length, snap=None):\n" +
        "        '''Read `length` bytes at `addr` (hex str or int) from trace memory. Returns hex string.\n" +
        "        For up-to-date bytes on a live target call refresh_memory(addr, length) first.'''\n" +
        "        try:\n" +
        "            trace = self.get_trace()\n" +
        "            if snap is None: snap = self.get_snap()\n" +
        "            if not trace or snap < 0: return 'no active trace'\n" +
        "            af = trace.getBaseAddressFactory()\n" +
        "            a = af.getDefaultAddressSpace().getAddress(addr if isinstance(addr, int) else int(str(addr), 16))\n" +
        "            import java.nio.ByteBuffer as ByteBuffer\n" +
        "            buf = ByteBuffer.allocate(length)\n" +
        "            read = trace.getMemoryManager().getBytes(snap, a, buf)\n" +
        "            buf.flip()\n" +
        "            ba = buf.array()\n" +
        "            return ''.join('%02x' % (b & 0xff) for b in ba[:read])\n" +
        "        except Exception as e: return 'error: ' + str(e)\n" +
        "    def refresh_memory(self, addr, length):\n" +
        "        '''Ask the live target to read memory into the trace (requires live session).'''\n" +
        "        try:\n" +
        "            trace = self.get_trace()\n" +
        "            target = self.get_target_service().getTarget(trace)\n" +
        "            if not target: return 'no target'\n" +
        "            af = trace.getBaseAddressFactory()\n" +
        "            a = af.getDefaultAddressSpace().getAddress(addr if isinstance(addr, int) else int(str(addr), 16))\n" +
        "            import ghidra.program.model.address.AddressSet as AddressSet\n" +
        "            aset = AddressSet(a, a.add(length - 1))\n" +
        "            target.readMemory(aset, monitor)\n" +
        "            return 'ok'\n" +
        "        except Exception as e: return 'error: ' + str(e)\n" +
        "    def _do_action(self, action_name_field, thread=None):\n" +
        "        '''Internal: dispatch a named action (RESUME/STEP_INTO/etc.) via Target.collectActions.\n" +
        "        Mirrors FlatDebuggerAPI.doThreadAction / doTraceAction.'''\n" +
        "        try:\n" +
        "            from ghidra.debug.api.target import ActionName\n" +
        "            from ghidra.debug.api.target import Target\n" +
        "            name = getattr(ActionName, action_name_field)\n" +
        "            if thread is None: thread = self.get_thread()\n" +
        "            trace = self.get_trace()\n" +
        "            if not trace: return 'no active trace'\n" +
        "            target = self.get_target_service().getTarget(trace)\n" +
        "            if not target: return 'no live target (trace may be read-only/emulation)'\n" +
        "            from docking import DefaultActionContext\n" +
        "            if thread is not None:\n" +
        "                try:\n" +
        "                    ctx = DefaultActionContext(None, thread.getObject(), None)\n" +
        "                except:\n" +
        "                    ctx = DefaultActionContext()\n" +
        "            else:\n" +
        "                ctx = DefaultActionContext()\n" +
        "            policy = Target.ObjectArgumentPolicy.CURRENT_OBJECT_IF_APPLICABLE\n" +
        "            actions = target.collectActions(name, ctx, policy)\n" +
        "            if not actions:\n" +
        "                return 'action ' + action_name_field + ' not available (wrong state?)'\n" +
        "            for entry in actions.values():\n" +
        "                entry.invoke(False)\n" +
        "                return 'ok'\n" +
        "        except Exception as e: return 'error: ' + str(e)\n" +
        "    def resume(self, thread=None):\n" +
        "        '''Resume execution of the current (or given) thread.'''\n" +
        "        return self._do_action('RESUME', thread)\n" +
        "    def interrupt(self, thread=None):\n" +
        "        '''Suspend/interrupt the current (or given) thread.'''\n" +
        "        return self._do_action('INTERRUPT', thread)\n" +
        "    def step_into(self, thread=None):\n" +
        "        '''Step into (single step) the current (or given) thread.'''\n" +
        "        return self._do_action('STEP_INTO', thread)\n" +
        "    def step_over(self, thread=None):\n" +
        "        '''Step over the current (or given) thread.'''\n" +
        "        return self._do_action('STEP_OVER', thread)\n" +
        "    def step_out(self, thread=None):\n" +
        "        '''Step out of the current function for the current (or given) thread.'''\n" +
        "        return self._do_action('STEP_OUT', thread)\n" +
        "    def kill(self, thread=None):\n" +
        "        '''Kill the target process.'''\n" +
        "        return self._do_action('KILL', thread)\n" +
        "    def list_breakpoints(self):\n" +
        "        '''List all logical breakpoints as list of {address, state, kinds, length} dicts.'''\n" +
        "        try:\n" +
        "            svc = self.get_bp_service()\n" +
        "            if not svc: return [{'error': 'DebuggerLogicalBreakpointService not loaded'}]\n" +
        "            result = []\n" +
        "            for bp in svc.getAllBreakpoints():\n" +
        "                try:\n" +
        "                    result.append({\n" +
        "                        'address': str(bp.getAddress()),\n" +
        "                        'state': bp.computeState().name(),\n" +
        "                        'kinds': str(bp.getKinds()),\n" +
        "                        'length': bp.getLength(),\n" +
        "                        'name': str(bp.getName()) if hasattr(bp, 'getName') else ''\n" +
        "                    })\n" +
        "                except Exception as e: result.append({'error': str(e)})\n" +
        "            return result\n" +
        "        except Exception as e: return [{'error': str(e)}]\n" +
        "    def set_breakpoint(self, addr, length=1, name=''):\n" +
        "        '''Place a software-execute breakpoint at addr in the current program.\n" +
        "        addr: hex string or int. Returns ok/error string.\n" +
        "        Requires a live target and static mapping between program and trace.'''\n" +
        "        try:\n" +
        "            from ghidra.app.services import DebuggerLogicalBreakpointService\n" +
        "            from ghidra.trace.model.breakpoint import TraceBreakpointKind\n" +
        "            svc = self.get_bp_service()\n" +
        "            if not svc: return 'DebuggerLogicalBreakpointService not loaded'\n" +
        "            prog_addr = currentProgram.getAddressFactory().getAddress(str(addr))\n" +
        "            kinds = java.util.Set.of(TraceBreakpointKind.SW_EXECUTE)\n" +
        "            future = svc.placeBreakpointAt(currentProgram, prog_addr, length, kinds, name)\n" +
        "            future.get()\n" +
        "            return 'ok: breakpoint at ' + str(addr)\n" +
        "        except Exception as e: return 'error: ' + str(e)\n" +
        "    def delete_breakpoints(self, addr):\n" +
        "        '''Delete all logical breakpoints at addr in the current program.'''\n" +
        "        try:\n" +
        "            svc = self.get_bp_service()\n" +
        "            if not svc: return 'DebuggerLogicalBreakpointService not loaded'\n" +
        "            prog_addr = currentProgram.getAddressFactory().getAddress(str(addr))\n" +
        "            bps = svc.getBreakpointsAt(currentProgram, prog_addr)\n" +
        "            if not bps: return 'no breakpoints at ' + str(addr)\n" +
        "            futures = [bp.delete() for bp in bps]\n" +
        "            for f in futures: f.get()\n" +
        "            return 'ok: deleted ' + str(len(futures)) + ' breakpoint(s) at ' + str(addr)\n" +
        "        except Exception as e: return 'error: ' + str(e)\n" +
        "    def get_stack(self, thread=None, snap=None):\n" +
        "        '''Stack frames for the current (or given) thread as list of {level, pc} dicts.\n" +
        "        pc is raw program-counter from the trace; use static mapping to resolve to symbols.'''\n" +
        "        try:\n" +
        "            if thread is None: thread = self.get_thread()\n" +
        "            if snap is None: snap = self.get_snap()\n" +
        "            if thread is None: return [{'error': 'no active thread'}]\n" +
        "            stack = thread.getStack(snap)\n" +
        "            if not stack: return []\n" +
        "            result = []\n" +
        "            for i, frame in enumerate(stack.getFrames()):\n" +
        "                result.append({'level': i, 'pc': hex(frame.getProgramCounter())})\n" +
        "            return result\n" +
        "        except Exception as e: return [{'error': str(e)}]\n" +
        "    def write_register(self, name, value, thread=None, frame=0, snap=None):\n" +
        "        '''Write a register value (int) for the current thread via StateEditor.\n" +
        "        Requires RW control mode (live target or emulation mode).'''\n" +
        "        try:\n" +
        "            from ghidra.app.services import DebuggerControlService\n" +
        "            from ghidra.program.model.lang import RegisterValue\n" +
        "            import java.math.BigInteger as BigInteger\n" +
        "            if thread is None: thread = self.get_thread()\n" +
        "            if snap is None: snap = self.get_snap()\n" +
        "            trace = thread.getTrace()\n" +
        "            reg = trace.getBaseLanguage().getRegister(name)\n" +
        "            if not reg: return 'register not found: ' + name\n" +
        "            rv = RegisterValue(reg, BigInteger.valueOf(value))\n" +
        "            ctrl_svc = self._svc('ghidra.app.services.DebuggerControlService')\n" +
        "            tm = self.get_trace_manager()\n" +
        "            coords = tm.getCurrent()\n" +
        "            editor = ctrl_svc.createStateEditor(coords)\n" +
        "            editor.setRegister(rv).get()\n" +
        "            return 'ok'\n" +
        "        except Exception as e: return 'error: ' + str(e)\n" +
        "    def write_memory(self, addr, hex_bytes):\n" +
        "        '''Write bytes (hex string) to live target memory via StateEditor.\n" +
        "        Requires RW control mode.'''\n" +
        "        try:\n" +
        "            trace = self.get_trace()\n" +
        "            if not trace: return 'no active trace'\n" +
        "            af = trace.getBaseAddressFactory()\n" +
        "            a = af.getDefaultAddressSpace().getAddress(addr if isinstance(addr, int) else int(str(addr), 16))\n" +
        "            raw = bytes(int(hex_bytes[i:i+2], 16) for i in range(0, len(hex_bytes), 2))\n" +
        "            ctrl_svc = self._svc('ghidra.app.services.DebuggerControlService')\n" +
        "            tm = self.get_trace_manager()\n" +
        "            editor = ctrl_svc.createStateEditor(tm.getCurrent())\n" +
        "            import jarray\n" +
        "            ba = jarray.array([(b if b < 128 else b - 256) for b in raw], 'b')\n" +
        "            editor.setVariable(a, ba).get()\n" +
        "            return 'ok'\n" +
        "        except Exception as e: return 'error: ' + str(e)\n" +
        "    def status(self):\n" +
        "        '''Summary dict of current debugger state. Check connected=True before other calls.'''\n" +
        "        try:\n" +
        "            trace = self.get_trace()\n" +
        "            if not trace:\n" +
        "                return {'connected': False, 'hint': 'Run `debugger status` for more details'}\n" +
        "            tm = self.get_trace_manager()\n" +
        "            thread = tm.getCurrentThread()\n" +
        "            snap = tm.getCurrentSnap()\n" +
        "            threads = self.get_threads()\n" +
        "            target_svc = self.get_target_service()\n" +
        "            target = target_svc.getTarget(trace) if target_svc else None\n" +
        "            return {\n" +
        "                'connected': True,\n" +
        "                'trace': trace.getName(),\n" +
        "                'snap': snap,\n" +
        "                'thread': str(thread) if thread else None,\n" +
        "                'thread_count': len(threads),\n" +
        "                'has_live_target': target is not None,\n" +
        "                'control_mode': str(self._svc('ghidra.app.services.DebuggerControlService').getCurrentMode(trace)) if self._svc('ghidra.app.services.DebuggerControlService') else 'unknown'\n" +
        "            }\n" +
        "        except Exception as e: return {'connected': False, 'error': str(e)}\n" +
        "dbg = DebuggerHelpers()\n\n";

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isLongRunning() {
        return true;
    }

    @Override
    public boolean isCacheable() {
        return false;
    }

    @Override
    public boolean isDestructive() {
        return true;
    }

    @Override
    public boolean isIdempotent() {
        return false;
    }

    @Override
    public String getName() {
        return "eval_python";
    }

    @Override
    public String getDescription() {
        return "Execute arbitrary Python code in Ghidra's context. Requires pyghidra.bat for Python 3 or uses Jython 2.7. " +
            "Agentic Prelude Active (call via 'ghidra.method'):\n" +
            "- decompile(id): Decompile func name/addr\n" +
            "- get_func(id): Return Function object\n" +
            "- get_program(name): Return open Program object by name\n" +
            "- get_vt_sessions(): Return list of all open VTSessions\n" +
            "- get_vt_session(idx=0): Return a VTSession by index\n" +
            "- list_vt_sessions(): Return [{name, src, dst, match_count}] for open sessions\n" +
            "- get_vt_matches(session=None, status=None): Return [{src, dst, status, similarity, confidence}]; status=ACCEPTED/REJECTED/AVAILABLE\n" +
            "- find_addr_in_version(addr, session=None): Find ACCEPTED destination address for a source address\n" +
            "- accept_vt_match(src_addr, session=None): Accept first AVAILABLE match for src address\n" +
            "- copy_datatype(name, from_prog, to_prog): Copy a Struct/Enum across binaries\n" +
            "- get_refs_to(addr): List of callers' addresses\n" +
            "- set_comment(addr, text, type='eol'|'pre'|'post'|'plate'): Set comment\n" +
            "- find_struct(name): Get Struct DT object\n" +
            "- read_bytes(addr, length): Hex memory read\n" +
            "- VT: VTSession and VTMatchInfo are auto-imported\n" +
            "Context provided: currentProgram, currentAddress, monitor.\n\n" +
            "Debugger Prelude Active (call via 'dbg.method') — requires Debugger plugin + active session:\n" +
            "  Session:     dbg.status() → {connected, trace, snap, thread, has_live_target, control_mode}\n" +
            "  Threads:     dbg.get_threads() → [TraceThread, ...]\n" +
            "               dbg.get_thread() → current TraceThread\n" +
            "               dbg.get_snap() → int\n" +
            "  Registers:   dbg.get_registers(thread=None, frame=0, snap=None) → {name: int}\n" +
            "               dbg.refresh_registers() → force live read into trace\n" +
            "               dbg.write_register(name, value) → ok/error\n" +
            "  Memory:      dbg.read_memory(addr, length, snap=None) → hex string\n" +
            "               dbg.refresh_memory(addr, length) → force live read into trace\n" +
            "               dbg.write_memory(addr, hex_bytes) → ok/error\n" +
            "  Execution:   dbg.resume() / dbg.interrupt() / dbg.step_into() / dbg.step_over() / dbg.step_out() / dbg.kill()\n" +
            "  Breakpoints: dbg.list_breakpoints() → [{address, state, kinds, length, name}]\n" +
            "               dbg.set_breakpoint(addr, length=1, name='') → ok/error\n" +
            "               dbg.delete_breakpoints(addr) → ok/error\n" +
            "  Stack:       dbg.get_stack(thread=None, snap=None) → [{level, pc}]\n" +
            "  Services:    dbg.get_trace() / dbg.get_trace_manager() / dbg.get_target_service() / dbg.get_bp_service()\n" +
            "  Workflow: call dbg.status() first; if connected=False use `debugger` tool to diagnose the session.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.ofEntries(
                Map.entry("script", Map.of(
                    "type", "string",
                    "description", "The Python script content to execute. Variables like 'currentProgram' and 'monitor' are globally available, just like a standard Ghidra Script."
                ))
            ),
            List.of("script"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return McpSchema.CallToolResult.builder()
            .addTextContent("Error: eval_python requires a backend reference.")
            .build();
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        String scriptContent = (String) arguments.get("script");
        if (scriptContent == null || scriptContent.trim().isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("script parameter is required")
                .build();
        }

        File tempFile = null;
        try {
            // Write out to a temp python file with PRELUDE
            tempFile = File.createTempFile("mcp_eval_", ".py");
            tempFile.deleteOnExit();
            try (FileWriter fw = new FileWriter(tempFile)) {
                fw.write(PRELUDE);
                fw.write(scriptContent);
            }

            ResourceFile sourceFile = new ResourceFile(tempFile);
            GhidraScriptProvider provider = GhidraScriptUtil.getProvider(sourceFile);
            if (provider == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Error: No GhidraScriptProvider found for .py extension. Check PyGhidra or Jython installation.")
                    .build();
            }

            StringWriter stringWriter = new StringWriter();
            PrintWriter printWriter = new PrintWriter(stringWriter);

            GhidraScript script = provider.getScriptInstance(sourceFile, printWriter);
            if (script == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Error: Could not obtain GhidraScript instance.")
                    .build();
            }

            // Prepare GhidraState with active context
            GhidraState state;
            GhidrAssistMCPPlugin plugin = backend.getActivePlugin();
            if (plugin != null && plugin.getTool() != null) {
                state = new GhidraState(plugin.getTool(), plugin.getTool().getProject(), currentProgram, null, null, null);
            } else {
                state = new GhidraState(null, null, currentProgram, null, null, null);
            }

            // Execute the script
            Msg.info(this, "Executing Python script evaluated from LLM...");
            ScriptControls controls = new ScriptControls(printWriter, printWriter, TaskMonitor.DUMMY);
            script.execute(state, controls);

            String output = stringWriter.toString();
            return McpSchema.CallToolResult.builder()
                .addTextContent(output.isEmpty() ? "Script executed successfully (no output)." : output)
                .build();

        } catch (Exception e) {
            Msg.error(this, "Error executing python script", e);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error executing script: " + e.getMessage() + "\n" + e.toString())
                .build();
        } finally {
            if (tempFile != null && tempFile.exists()) {
                tempFile.delete();
            }
        }
    }
}
