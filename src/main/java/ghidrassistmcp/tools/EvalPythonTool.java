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
        "dbg = DebuggerHelpers()\n\n" +
        // ── Reverse-engineering helpers ────────────────────────────────────────────────
        // Injected as `reng`. Game/platform-agnostic utilities for dynamic RE.
        // Works with or without a live debugger session.
        //
        // ReClass.NET workflow (live struct exploration):
        //   reng.explore(rt_addr)         → field table with auto-type interpretation
        //   reng.rtti(rt_ptr)             → decode MSVC x64 RTTI class name
        //   reng.read_struct(rt_addr, fields) → read named fields at offsets
        //   reng.define_struct(name, fields)  → create/update StructureDataType in Ghidra
        //   reng.apply_struct(rt_addr, name)  → apply named struct at static address
        //
        // Address conversion (ASLR):
        //   reng.image_base()             → runtime image base (inferred from debugger)
        //   reng.to_rt(static_addr)       → static Ghidra addr → runtime addr
        //   reng.to_static(rt_addr)       → runtime addr → static Ghidra addr
        //
        // RTTI/vtable scanner (builds vtable→class map from static .rdata):
        //   reng.scan_vtables(prog=None)  → {vtable_static_addr: class_name} — scans RTTI
        //   reng.rename_vfuncs(vtable_map) → bulk-rename FUN_* into class namespaces
        "class REngHelpers:\n" +
        "    '''Platform-agnostic reverse engineering utilities. Works best with dbg connected.\n" +
        "    Workflow: reng.image_base() → reng.rtti(ptr) → reng.explore(ptr) → reng.define_struct(...)\n" +
        "    MSVC x64 RTTI layout: obj[0]=vtable_ptr, vtable[-8]=RTTICompleteObjectLocator (COL),\n" +
        "      COL+0=sig(1), COL+12=TypeDescriptor_RVA, TypeDescriptor+16=mangled_name(.?AV<class>@@)\n" +
        "    '''\n" +
        "    _image_base_cache = None\n" +
        "    _vtable_cache = None\n" +
        "\n" +
        "    def image_base(self):\n" +
        "        '''Runtime image base of currentProgram binary. Inferred from debugger thread names.\n" +
        "        Returns int or None if no debugger session.'''\n" +
        "        if self._image_base_cache: return self._image_base_cache\n" +
        "        import re as _re\n" +
        "        prog_name = currentProgram.getName().replace('.exe','') if currentProgram else ''\n" +
        "        static_base = currentProgram.getImageBase().getOffset() if currentProgram else 0x140000000\n" +
        "        try:\n" +
        "            for t in dbg.get_threads():\n" +
        "                name = t.getName(0)\n" +
        "                # Match: ModuleName!FuncName+0xOFF (0xADDR) or similar WinDbg format\n" +
        "                m = _re.search(r'%s![^+\\s]+\\+0x([0-9a-fA-F]+)\\s+\\(([0-9a-fA-F`]+)\\)' % _re.escape(prog_name), name, _re.I)\n" +
        "                if not m:\n" +
        "                    m = _re.search(r'%s!([^+\\s]+)\\+0x([0-9a-fA-F]+)' % _re.escape(prog_name), name, _re.I)\n" +
        "                if m:\n" +
        "                    groups = m.groups()\n" +
        "                    offset = int(groups[-2], 16)\n" +
        "                    rt_pc  = int(groups[-1].replace('`',''), 16)\n" +
        "                    rt_fn  = rt_pc - offset\n" +
        "                    # Find the static function address from the display name\n" +
        "                    full = name\n" +
        "                    fn_m = _re.search(r'%s!(FUN_([0-9a-fA-F]+))' % _re.escape(prog_name), full, _re.I)\n" +
        "                    if fn_m:\n" +
        "                        static_fn = int(fn_m.group(2), 16)\n" +
        "                        self._image_base_cache = rt_fn - (static_fn - static_base)\n" +
        "                        return self._image_base_cache\n" +
        "        except Exception as e: pass\n" +
        "        return None\n" +
        "\n" +
        "    def to_rt(self, static_addr):\n" +
        "        '''Convert static Ghidra address to runtime address (applies ASLR offset).'''\n" +
        "        ib = self.image_base()\n" +
        "        sb = currentProgram.getImageBase().getOffset() if currentProgram else 0x140000000\n" +
        "        return static_addr - sb + ib if ib else None\n" +
        "\n" +
        "    def to_static(self, rt_addr):\n" +
        "        '''Convert runtime address to static Ghidra address (removes ASLR offset).'''\n" +
        "        ib = self.image_base()\n" +
        "        sb = currentProgram.getImageBase().getOffset() if currentProgram else 0x140000000\n" +
        "        return rt_addr - ib + sb if ib else None\n" +
        "\n" +
        "    def _read_mem_static(self, static_addr, n):\n" +
        "        '''Read n bytes from static Ghidra program memory. Returns bytes or None.'''\n" +
        "        try:\n" +
        "            mem = currentProgram.getMemory()\n" +
        "            ds  = currentProgram.getAddressFactory().getDefaultAddressSpace()\n" +
        "            a   = ds.getAddress(static_addr)\n" +
        "            buf = bytearray(n)\n" +
        "            for i in range(n): buf[i] = mem.getByte(a.add(i)) & 0xff\n" +
        "            return bytes(buf)\n" +
        "        except: return None\n" +
        "\n" +
        "    def _read_rt(self, rt_addr, n):\n" +
        "        '''Read n bytes from live trace memory. Returns bytes or None.'''\n" +
        "        try:\n" +
        "            hex_data = dbg.read_memory(rt_addr, n)\n" +
        "            if 'error' in hex_data: return None\n" +
        "            return bytes.fromhex(hex_data[:n*2])\n" +
        "        except: return None\n" +
        "\n" +
        "    def rtti(self, rt_obj_ptr):\n" +
        "        '''Decode MSVC x64 RTTI class name from a live object pointer.\n" +
        "        Reads vtable ptr at [obj], then COL at vtable[-8], then TypeDescriptor.\n" +
        "        Returns class name string or None.'''\n" +
        "        import re as _re, struct as _st\n" +
        "        try:\n" +
        "            # Read vtable pointer at offset 0 of object\n" +
        "            b = self._read_rt(rt_obj_ptr, 8)\n" +
        "            if not b: return None\n" +
        "            vtable_rt = _st.unpack_from('<Q', b)[0]\n" +
        "            # Read COL pointer at vtable[-8]\n" +
        "            b = self._read_rt(vtable_rt - 8, 8)\n" +
        "            if not b: return None\n" +
        "            col_rt = _st.unpack_from('<Q', b)[0]\n" +
        "            # Convert COL to static and read from program memory\n" +
        "            col_static = self.to_static(col_rt)\n" +
        "            if not col_static: return None\n" +
        "            col_bytes = self._read_mem_static(col_static, 24)\n" +
        "            if not col_bytes or len(col_bytes) < 24: return None\n" +
        "            sig = _st.unpack_from('<I', col_bytes, 0)[0]\n" +
        "            if sig != 1: return None  # not x64 COL\n" +
        "            td_rva = _st.unpack_from('<I', col_bytes, 12)[0]\n" +
        "            sb = currentProgram.getImageBase().getOffset()\n" +
        "            td_static = sb + td_rva\n" +
        "            # TypeDescriptor+16 = mangled name\n" +
        "            name_bytes = self._read_mem_static(td_static + 16, 128)\n" +
        "            if not name_bytes: return None\n" +
        "            name = name_bytes.split(b'\\x00')[0].decode('ascii', errors='replace')\n" +
        "            m = _re.match(r'\\.\\?A[VUW]([^@]+)@', name)\n" +
        "            return m.group(1) if m else name\n" +
        "        except: return None\n" +
        "\n" +
        "    def explore(self, rt_addr, size=256):\n" +
        "        '''ReClass.NET-style live struct explorer.\n" +
        "        Reads `size` bytes at runtime address, interprets each 8-byte slot as:\n" +
        "          ptr (→ RTTI class if SkyrimSE range), i64, f32, f64.\n" +
        "        Auto-identifies vtable slot (offset 0), function pointers, null fields.\n" +
        "        Returns formatted string table. Use to discover struct layout interactively.'''\n" +
        "        import struct as _st\n" +
        "        ib = self.image_base()\n" +
        "        sb = currentProgram.getImageBase().getOffset() if currentProgram else 0\n" +
        "        fm = currentProgram.getFunctionManager() if currentProgram else None\n" +
        "        ds = currentProgram.getAddressFactory().getDefaultAddressSpace() if currentProgram else None\n" +
        "        # Fetch memory\n" +
        "        dbg.refresh_memory(rt_addr, size)\n" +
        "        raw = self._read_rt(rt_addr, size)\n" +
        "        if not raw: return 'Error: could not read 0x%x' % rt_addr\n" +
        "        rtti_name = self.rtti(rt_addr)\n" +
        "        lines = ['=== 0x%x  (%s)  %d bytes ===' % (rt_addr, rtti_name or '?', len(raw)),\n" +
        "                 '%-6s %-16s %-22s %-12s %-12s  %s' % ('Off','Hex(LE)','As ptr','As i32/i64','As f32','Note')]\n" +
        "        for off in range(0, len(raw) - 7, 8):\n" +
        "            chunk = raw[off:off+8]\n" +
        "            u64   = _st.unpack_from('<Q', chunk)[0]\n" +
        "            i32   = _st.unpack_from('<i', chunk[:4])[0]\n" +
        "            f32   = _st.unpack_from('<f', chunk[:4])[0]\n" +
        "            note  = ''\n" +
        "            ptr_str = ''\n" +
        "            if u64 == 0:\n" +
        "                note = 'null'\n" +
        "            elif ib and ib <= u64 < ib + 0x10000000:\n" +
        "                static = u64 - ib + sb\n" +
        "                try:\n" +
        "                    fn = fm.getFunctionAt(ds.getAddress(static)) if fm else None\n" +
        "                    if fn:\n" +
        "                        ptr_str = fn.getName(True)\n" +
        "                        note = 'fn-ptr'\n" +
        "                    else:\n" +
        "                        # Could be vtable or object ptr\n" +
        "                        if off == 0:\n" +
        "                            note = 'vtable → %s' % (rtti_name or '?')\n" +
        "                        else:\n" +
        "                            sub_rtti = self.rtti(u64)\n" +
        "                            ptr_str = '0x%x' % u64\n" +
        "                            note = 'ptr→%s' % (sub_rtti if sub_rtti else 'SkyrimSE')\n" +
        "                except: ptr_str = '0x%x' % u64\n" +
        "            elif 0x7f0000000000 <= u64 <= 0x7fffffffffff:\n" +
        "                ptr_str = '0x%x' % u64\n" +
        "                note = 'ptr→DLL/heap'\n" +
        "            elif 0 < u64 < 0x10000:\n" +
        "                note = 'small_int=%d' % u64\n" +
        "            elif abs(f32) > 1e-10 and abs(f32) < 1e8 and f32 == f32:  # not NaN, reasonable range\n" +
        "                note = 'f32≈%.5g' % f32\n" +
        "            lines.append('+%-5x %-16s %-22s %-12d %-12.5g  %s' % (\n" +
        "                off, chunk.hex()[:16], ptr_str[:22], i32, f32, note))\n" +
        "        return '\\n'.join(lines)\n" +
        "\n" +
        "    def read_struct(self, rt_addr, fields):\n" +
        "        '''Read named fields from a live object at rt_addr.\n" +
        "        fields = {name: (offset, type_str)}\n" +
        "        type_str: u8/u16/u32/u64/i8/i16/i32/i64/f32/f64/ptr/cstr/wstr\n" +
        "        Returns {name: value} dict. Example:\n" +
        "          reng.read_struct(player_ptr, {\"health\":(0x54,\"f32\"), \"pos_x\":(0xD0,\"f32\")})\n" +
        "        '''\n" +
        "        import struct as _st\n" +
        "        fmt = {'u8':('<B',1),'u16':('<H',2),'u32':('<I',4),'u64':('<Q',8),\n" +
        "               'i8':('<b',1),'i16':('<h',2),'i32':('<i',4),'i64':('<q',8),\n" +
        "               'f32':('<f',4),'f64':('<d',8),'ptr':('<Q',8)}\n" +
        "        result = {}\n" +
        "        for name, (off, typ) in fields.items():\n" +
        "            addr = rt_addr + off\n" +
        "            if typ in ('cstr', 'wstr'):\n" +
        "                ptr_raw = self._read_rt(addr, 8)\n" +
        "                ptr = _st.unpack_from('<Q', ptr_raw)[0] if ptr_raw else 0\n" +
        "                if ptr:\n" +
        "                    s_raw = self._read_rt(ptr, 128)\n" +
        "                    if s_raw:\n" +
        "                        if typ == 'wstr': result[name] = s_raw.decode('utf-16-le', errors='replace').split('\\x00')[0]\n" +
        "                        else: result[name] = s_raw.split(b'\\x00')[0].decode('utf-8', errors='replace')\n" +
        "                    else: result[name] = None\n" +
        "                else: result[name] = None\n" +
        "            elif typ in fmt:\n" +
        "                f, sz = fmt[typ]\n" +
        "                b = self._read_rt(addr, sz)\n" +
        "                result[name] = _st.unpack(f, b)[0] if b else None\n" +
        "            else: result[name] = 'unknown type: ' + typ\n" +
        "        return result\n" +
        "\n" +
        "    def define_struct(self, name, fields, category='/'):\n" +
        "        '''Create or update a StructureDataType in Ghidra's data type manager.\n" +
        "        fields = {field_name: (offset, size, comment)}\n" +
        "        If a struct with this name already exists, existing named fields are PRESERVED\n" +
        "        and only new/overlapping fields from `fields` are added/updated.\n" +
        "        Returns the StructureDataType or error string.\n" +
        "        Tip: call with fields={} to inspect an existing struct definition.'''\n" +
        "        from ghidra.program.model.data import StructureDataType, CategoryPath, DataTypeConflictHandler\n" +
        "        from ghidra.program.model.data import ByteDataType, DWordDataType, QWordDataType, FloatDataType, Undefined\n" +
        "        dtm = currentProgram.getDataTypeManager()\n" +
        "        cat = CategoryPath(category)\n" +
        "        size_to_dt = {1: ByteDataType.dataType, 2: Undefined.getUndefinedDataType(2),\n" +
        "                      4: DWordDataType.dataType, 8: QWordDataType.dataType}\n" +
        "        # Check for existing struct\n" +
        "        existing = None\n" +
        "        for dt in dtm.getAllDataTypes():\n" +
        "            if dt.getName() == name and hasattr(dt, 'getComponents'):\n" +
        "                existing = dt\n" +
        "                break\n" +
        "        if existing is not None and not fields:\n" +
        "            # Inspection mode: return summary of existing struct\n" +
        "            lines = ['Existing struct %s (%d bytes):' % (name, existing.getLength())]\n" +
        "            for comp in existing.getComponents():\n" +
        "                fname = comp.getFieldName() or ''\n" +
        "                lines.append('  +0x%x  %-4d  %-20s  %s' % (\n" +
        "                    comp.getOffset(), comp.getLength(),\n" +
        "                    fname, comp.getComment() or ''))\n" +
        "            return '\\n'.join(lines)\n" +
        "        # Build merged field map: start from existing, override/add with new fields\n" +
        "        merged = {}  # offset -> (fname, size, comment)\n" +
        "        if existing is not None:\n" +
        "            for comp in existing.getComponents():\n" +
        "                fname = comp.getFieldName()\n" +
        "                if fname:  # only preserve named fields\n" +
        "                    merged[comp.getOffset()] = (fname, comp.getLength(), comp.getComment() or '')\n" +
        "        for fname, (off, sz, comment) in fields.items():\n" +
        "            merged[off] = (fname, sz, comment)\n" +
        "        # Determine struct size\n" +
        "        if merged:\n" +
        "            total = max(off + sz for off, (_, sz, _) in merged.items())\n" +
        "        elif existing:\n" +
        "            total = existing.getLength()\n" +
        "        else:\n" +
        "            total = 1\n" +
        "        st2 = StructureDataType(cat, name, total, dtm)\n" +
        "        for off, (fname, sz, comment) in sorted(merged.items()):\n" +
        "            dt = size_to_dt.get(sz, ByteDataType.dataType)\n" +
        "            try: st2.insertAtOffset(off, dt, sz, fname, comment)\n" +
        "            except: pass\n" +
        "        tx = currentProgram.startTransaction('define_struct: ' + name)\n" +
        "        try:\n" +
        "            result = dtm.addDataType(st2, DataTypeConflictHandler.REPLACE_HANDLER)\n" +
        "            currentProgram.endTransaction(tx, True)\n" +
        "            return result\n" +
        "        except Exception as e:\n" +
        "            currentProgram.endTransaction(tx, False)\n" +
        "            return 'error: ' + str(e)\n" +
        "\n" +
        "    def scan_vtables(self, prog=None):\n" +
        "        '''Scan RTTI in .rdata and return {vtable_static_addr: class_name}.\n" +
        "        Uses native Memory.findBytes — fast. Results are cached after first call.\n" +
        "        Equivalent to scanning for all MSVC class vtables in a PE binary.'''\n" +
        "        if self._vtable_cache: return self._vtable_cache\n" +
        "        import re as _re, struct as _st\n" +
        "        import ghidra.util.task.TaskMonitor as _TM\n" +
        "        p   = prog or currentProgram\n" +
        "        mem = p.getMemory()\n" +
        "        ds  = p.getAddressFactory().getDefaultAddressSpace()\n" +
        "        rm  = p.getReferenceManager()\n" +
        "        sb  = p.getImageBase().getOffset()\n" +
        "        def r32(a):\n" +
        "            try:\n" +
        "                addr = ds.getAddress(a); b = bytearray(4)\n" +
        "                for i in range(4): b[i] = mem.getByte(addr.add(i)) & 0xff\n" +
        "                return _st.unpack('<I', bytes(b))[0]\n" +
        "            except: return None\n" +
        "        def rstr(a):\n" +
        "            try:\n" +
        "                addr = ds.getAddress(a); s = []\n" +
        "                for i in range(128):\n" +
        "                    c = mem.getByte(addr.add(i)) & 0xff\n" +
        "                    if c == 0: break\n" +
        "                    s.append(chr(c))\n" +
        "                return ''.join(s)\n" +
        "            except: return ''\n" +
        "        rdata = next((b for b in mem.getBlocks() if b.getName() == '.rdata'), None)\n" +
        "        if not rdata: return {}\n" +
        "        cols = {}\n" +
        "        search = rdata.getStart()\n" +
        "        end    = rdata.getEnd()\n" +
        "        while True:\n" +
        "            hit = mem.findBytes(search, bytes([1,0,0,0]), None, True, _TM.DUMMY)\n" +
        "            if hit is None or hit.compareTo(end) >= 0: break\n" +
        "            a = hit.getOffset()\n" +
        "            self_rva = r32(a + 20)\n" +
        "            if self_rva and sb + self_rva == a:\n" +
        "                td_rva = r32(a + 12)\n" +
        "                if td_rva:\n" +
        "                    name = rstr(sb + td_rva + 16)\n" +
        "                    if name.startswith('.?'):\n" +
        "                        m = _re.match(r'\\.\\?A[VUW]([^@]+)@', name)\n" +
        "                        cols[a] = m.group(1) if m else name\n" +
        "            search = ds.getAddress(a + 4)\n" +
        "        vtmap = {}\n" +
        "        for col_addr, class_name in cols.items():\n" +
        "            col_ghidra = ds.getAddress(col_addr)\n" +
        "            for ref in rm.getReferencesTo(col_ghidra):\n" +
        "                vtmap[ref.getFromAddress().getOffset() + 8] = class_name\n" +
        "        self._vtable_cache = vtmap\n" +
        "        return vtmap\n" +
        "\n" +
        "    def rename_vfuncs(self, vtable_map=None, dry_run=False):\n" +
        "        '''Bulk-rename FUN_* functions using vtable map from scan_vtables().\n" +
        "        Assigns Class::vfunc_N names. Skips already-named functions.\n" +
        "        Returns {renamed: N, skipped: N, errors: N}.'''\n" +
        "        import re as _re\n" +
        "        from ghidra.program.model.symbol import SourceType\n" +
        "        vtmap = vtable_map or self.scan_vtables()\n" +
        "        p  = currentProgram\n" +
        "        mem = p.getMemory()\n" +
        "        ds  = p.getAddressFactory().getDefaultAddressSpace()\n" +
        "        fm  = p.getFunctionManager()\n" +
        "        st2 = p.getSymbolTable()\n" +
        "        def r64(a):\n" +
        "            try:\n" +
        "                addr = ds.getAddress(a); b = bytearray(8)\n" +
        "                for i in range(8): b[i] = mem.getByte(addr.add(i)) & 0xff\n" +
        "                import struct as _s; return _s.unpack('<Q', bytes(b))[0]\n" +
        "            except: return None\n" +
        "        renamed = skipped = errors = 0\n" +
        "        tx = p.startTransaction('reng.rename_vfuncs') if not dry_run else None\n" +
        "        try:\n" +
        "            for vt, class_name in vtmap.items():\n" +
        "                ns_name = _re.sub(r'[<>$,\\s]', '_', class_name)[:64]\n" +
        "                try:\n" +
        "                    ns = st2.getNamespace(ns_name, p.getGlobalNamespace())\n" +
        "                    if ns is None and not dry_run:\n" +
        "                        ns = st2.createNameSpace(p.getGlobalNamespace(), ns_name, SourceType.ANALYSIS)\n" +
        "                except: skipped += 1; continue\n" +
        "                idx = 0\n" +
        "                ptr = vt\n" +
        "                while idx < 512:\n" +
        "                    fn_addr = r64(ptr)\n" +
        "                    if not fn_addr: break\n" +
        "                    sb = p.getImageBase().getOffset()\n" +
        "                    if fn_addr < sb or fn_addr > sb + 0x10000000: break\n" +
        "                    fn = fm.getFunctionAt(ds.getAddress(fn_addr))\n" +
        "                    if fn is None: break\n" +
        "                    cur = fn.getName()\n" +
        "                    if cur.startswith('FUN_') or cur.startswith('thunk_FUN_'):\n" +
        "                        if not dry_run:\n" +
        "                            try: fn.setName('vfunc_%d' % idx, SourceType.ANALYSIS); fn.setParentNamespace(ns); renamed += 1\n" +
        "                            except: errors += 1\n" +
        "                        else: renamed += 1\n" +
        "                    else:\n" +
        "                        skipped += 1\n" +
        "                        if not dry_run:\n" +
        "                            try:\n" +
        "                                if fn.getParentNamespace().isGlobal(): fn.setParentNamespace(ns)\n" +
        "                            except: pass\n" +
        "                    ptr += 8; idx += 1\n" +
        "            if tx is not None: p.endTransaction(tx, True)\n" +
        "        except Exception as e:\n" +
        "            if tx is not None: p.endTransaction(tx, False)\n" +
        "            return {'error': str(e)}\n" +
        "        return {'renamed': renamed, 'skipped': skipped, 'errors': errors}\n" +
        "\n" +
        "    def follow(self, rt_addr, offset, size=256):\n" +
        "        '''Follow a pointer at [rt_addr+offset] and explore the pointed-to object.\n" +
        "        Core ReClass.NET workflow: see a candidate ptr in explore(), follow it here.\n" +
        "        Returns explore() output for the sub-object, or error string.'''\n" +
        "        import struct as _st\n" +
        "        b = self._read_rt(rt_addr + offset, 8)\n" +
        "        if not b: return 'Error: could not read ptr at 0x%x+0x%x' % (rt_addr, offset)\n" +
        "        sub_ptr = _st.unpack_from('<Q', b)[0]\n" +
        "        if sub_ptr == 0: return 'Null pointer at offset 0x%x' % offset\n" +
        "        print('Following ptr @ +0x%x: 0x%x -> 0x%x' % (offset, rt_addr + offset, sub_ptr))\n" +
        "        return self.explore(sub_ptr, size)\n" +
        "\n" +
        "    def as_array(self, rt_addr, offset, count, type_str='f32'):\n" +
        "        '''Read `count` consecutive values of `type_str` starting at rt_addr+offset.\n" +
        "        Useful for: XYZ positions (3xf32), rotation matrices (9xf32), arrays of IDs (Nxu32).\n" +
        "        type_str: f32/f64/u8/u16/u32/u64/i32/i64/ptr\n" +
        "        Example: reng.as_array(actor_ptr, 0xD0, 3, \"f32\") → [x, y, z]'''\n" +
        "        import struct as _st\n" +
        "        fmt_map = {'f32':('<f',4),'f64':('<d',8),'u8':('<B',1),'u16':('<H',2),\n" +
        "                   'u32':('<I',4),'u64':('<Q',8),'i32':('<i',4),'i64':('<q',8),'ptr':('<Q',8)}\n" +
        "        if type_str not in fmt_map: return 'Unknown type: ' + type_str\n" +
        "        fmt, sz = fmt_map[type_str]\n" +
        "        total = count * sz\n" +
        "        raw = self._read_rt(rt_addr + offset, total)\n" +
        "        if not raw: return 'Error reading %d bytes at 0x%x+0x%x' % (total, rt_addr, offset)\n" +
        "        result = [_st.unpack_from(fmt, raw, i*sz)[0] for i in range(count)]\n" +
        "        return result\n" +
        "\n" +
        "    def diff(self, rt_addr1, rt_addr2, size=256, threshold=0):\n" +
        "        '''Compare two struct instances field-by-field to find which offsets differ.\n" +
        "        Key ReClass.NET technique: find two objects of the same class (e.g. two Actors),\n" +
        "        change one (take damage, move), diff them → differing offsets = health/position/etc.\n" +
        "        Returns list of {offset, val1, val2, delta} for differing 8-byte slots.'''\n" +
        "        import struct as _st\n" +
        "        dbg.refresh_memory(rt_addr1, size)\n" +
        "        dbg.refresh_memory(rt_addr2, size)\n" +
        "        raw1 = self._read_rt(rt_addr1, size)\n" +
        "        raw2 = self._read_rt(rt_addr2, size)\n" +
        "        if not raw1 or not raw2: return 'Error reading memory'\n" +
        "        diffs = []\n" +
        "        n = min(len(raw1), len(raw2))\n" +
        "        for off in range(0, n - 7, 8):\n" +
        "            v1 = _st.unpack_from('<Q', raw1, off)[0]\n" +
        "            v2 = _st.unpack_from('<Q', raw2, off)[0]\n" +
        "            if v1 != v2:\n" +
        "                delta = abs(v2 - v1) if v2 >= v1 else abs(v1 - v2)\n" +
        "                if delta > threshold:\n" +
        "                    f1 = _st.unpack_from('<f', raw1, off)[0]\n" +
        "                    f2 = _st.unpack_from('<f', raw2, off)[0]\n" +
        "                    diffs.append({'offset': off, 'hex_off': '+0x%x' % off,\n" +
        "                                  'val1': v1, 'val2': v2, 'delta': delta,\n" +
        "                                  'as_f32_1': f1, 'as_f32_2': f2})\n" +
        "        print('Diff 0x%x vs 0x%x: %d differing slots out of %d' % (rt_addr1, rt_addr2, len(diffs), n//8))\n" +
        "        return diffs\n" +
        "\n" +
        "    def class_hierarchy(self, rt_ptr):\n" +
        "        '''Decode full MSVC RTTI inheritance chain for a live object.\n" +
        "        Returns ordered list of {class, offset, bases} from most-derived to base.\n" +
        "        NOTE: RTTI stores class NAMES and BASE OFFSETS, not vfunc names.\n" +
        "        Use vtable_methods() to see the actual virtual functions by slot.'''\n" +
        "        import struct as _st\n" +
        "        try:\n" +
        "            b = self._read_rt(rt_ptr, 8)\n" +
        "            if not b: return [{'error': 'cannot read object'}]\n" +
        "            vtable_rt = _st.unpack_from('<Q', b)[0]\n" +
        "            b2 = self._read_rt(vtable_rt - 8, 8)\n" +
        "            if not b2: return [{'error': 'cannot read vtable[-8]'}]\n" +
        "            col_rt = _st.unpack_from('<Q', b2)[0]\n" +
        "            col_static = self.to_static(col_rt)\n" +
        "            if not col_static: return [{'error': 'address conversion failed'}]\n" +
        "            col_bytes = self._read_mem_static(col_static, 24)\n" +
        "            if not col_bytes or col_bytes[0] != 1: return [{'error': 'invalid COL'}]\n" +
        "            sb = currentProgram.getImageBase().getOffset()\n" +
        "            # RTTIClassHierarchyDescriptor RVA is at COL+16\n" +
        "            chd_rva  = _st.unpack_from('<I', col_bytes, 16)[0]\n" +
        "            chd_static = sb + chd_rva\n" +
        "            chd_bytes  = self._read_mem_static(chd_static, 12)\n" +
        "            if not chd_bytes: return [{'error': 'cannot read CHD'}]\n" +
        "            num_bases  = _st.unpack_from('<I', chd_bytes, 8)[0]\n" +
        "            bca_rva    = _st.unpack_from('<I', chd_bytes, 4)[0]  # wait, offset 4 is attrs, 8 is numBases\n" +
        "            # CHD layout: +0=sig, +4=attrs, +8=numBases, +12=pBaseClassArray(RVA)\n" +
        "            chd_bytes12 = self._read_mem_static(chd_static, 16)\n" +
        "            num_bases   = _st.unpack_from('<I', chd_bytes12, 8)[0]\n" +
        "            bca_rva     = _st.unpack_from('<I', chd_bytes12, 12)[0]\n" +
        "            bca_static  = sb + bca_rva\n" +
        "            result = []\n" +
        "            import re as _re\n" +
        "            for i in range(min(num_bases, 64)):\n" +
        "                bcd_rva   = self._read_mem_static(bca_static + i * 4, 4)\n" +
        "                if not bcd_rva: break\n" +
        "                bcd_static = sb + _st.unpack_from('<I', bcd_rva)[0]\n" +
        "                bcd_bytes  = self._read_mem_static(bcd_static, 28)\n" +
        "                if not bcd_bytes: break\n" +
        "                td_rva  = _st.unpack_from('<I', bcd_bytes, 0)[0]\n" +
        "                mdisp   = _st.unpack_from('<i', bcd_bytes, 8)[0]   # offset within object\n" +
        "                name_bytes = self._read_mem_static(sb + td_rva + 16, 128)\n" +
        "                if not name_bytes: continue\n" +
        "                raw_name = name_bytes.split(b'\\x00')[0].decode('ascii', errors='replace')\n" +
        "                m = _re.match(r'\\.\\?A[VUW]([^@]+)@', raw_name)\n" +
        "                class_name = m.group(1) if m else raw_name\n" +
        "                result.append({'class': class_name, 'offset': mdisp, 'index': i})\n" +
        "            return result\n" +
        "        except Exception as e: return [{'error': str(e)}]\n" +
        "\n" +
        "    def vtable_methods(self, rt_ptr, max_vfuncs=128):\n" +
        "        '''List virtual functions in the vtable of a live object.\n" +
        "        Shows slot index, runtime addr, static addr, and current Ghidra name.\n" +
        "        NOTE: RTTI gives class/hierarchy names only. Vfunc NAMES come from:\n" +
        "          - Ghidra analysis / prior renaming (e.g. from reng.rename_vfuncs())\n" +
        "          - SKSE/CommonLibSSE header imports applied to the project\n" +
        "          - Manual identification via dynamic tracing\n" +
        "        Returns list of {slot, rt_addr, static_addr, name, named} dicts.'''\n" +
        "        import struct as _st\n" +
        "        ib = self.image_base()\n" +
        "        sb = currentProgram.getImageBase().getOffset() if currentProgram else 0\n" +
        "        fm = currentProgram.getFunctionManager() if currentProgram else None\n" +
        "        ds = currentProgram.getAddressFactory().getDefaultAddressSpace() if currentProgram else None\n" +
        "        try:\n" +
        "            b = self._read_rt(rt_ptr, 8)\n" +
        "            vtable_rt = _st.unpack_from('<Q', b)[0]\n" +
        "            rtti_name = self.rtti(rt_ptr)\n" +
        "            print('vtable @ 0x%x  class=%s' % (vtable_rt, rtti_name or '?'))\n" +
        "            result = []\n" +
        "            for i in range(max_vfuncs):\n" +
        "                fn_bytes = self._read_rt(vtable_rt + i * 8, 8)\n" +
        "                if not fn_bytes: break\n" +
        "                fn_rt = _st.unpack_from('<Q', fn_bytes)[0]\n" +
        "                if ib and not (ib <= fn_rt < ib + 0x10000000): break\n" +
        "                fn_static = fn_rt - ib + sb if ib else fn_rt\n" +
        "                name = '???'\n" +
        "                named = False\n" +
        "                if fm and ds:\n" +
        "                    try:\n" +
        "                        fn = fm.getFunctionAt(ds.getAddress(fn_static))\n" +
        "                        if fn:\n" +
        "                            name = fn.getName(True)  # include namespace\n" +
        "                            named = not fn.getName().startswith('FUN_')\n" +
        "                    except: pass\n" +
        "                result.append({'slot': i, 'rt': hex(fn_rt), 'static': hex(fn_static),\n" +
        "                               'name': name, 'named': named})\n" +
        "            named_count = sum(1 for r in result if r['named'])\n" +
        "            print('%d vfuncs, %d named, %d unnamed' % (len(result), named_count, len(result)-named_count))\n" +
        "            return result\n" +
        "        except Exception as e: return [{'error': str(e)}]\n" +
        "\n" +
        "    def _scripts_dir(self):\n" +
        "        '''Return the primary user Ghidra scripts directory path.'''\n" +
        "        try:\n" +
        "            from ghidra.app.script import GhidraScriptUtil\n" +
        "            dirs = GhidraScriptUtil.getScriptSourceDirectories()\n" +
        "            if dirs: return str(dirs[0])\n" +
        "        except: pass\n" +
        "        import os\n" +
        "        return os.path.join(os.path.expanduser('~'), 'ghidra_scripts')\n" +
        "\n" +
        "    def save_script(self, name, code, category='MCP', description=''):\n" +
        "        '''Save a Python script to the Ghidra scripts directory so it appears in Script Manager.\n" +
        "        name: filename without path (e.g. \"FindActors.py\")\n" +
        "        code: the Python script content\n" +
        "        category: Script Manager category (default \"MCP\")\n" +
        "        description: short description shown in Script Manager\n" +
        "        Scripts must be runnable as GhidraScripts — use currentProgram, monitor, etc.\n" +
        "        Prepends @category/@description metadata if not already present.\n" +
        "        Returns the full path written.'''\n" +
        "        import os\n" +
        "        scripts_dir = self._scripts_dir()\n" +
        "        if not os.path.isdir(scripts_dir):\n" +
        "            os.makedirs(scripts_dir, exist_ok=True)\n" +
        "        # Prepend script metadata if not present\n" +
        "        header = ''\n" +
        "        if '@category' not in code:\n" +
        "            header += '# @category %s\\n' % category\n" +
        "        if description and '@description' not in code:\n" +
        "            header += '# @description %s\\n' % description\n" +
        "        if not name.endswith('.py'): name += '.py'\n" +
        "        full_path = os.path.join(scripts_dir, name)\n" +
        "        with open(full_path, 'w', encoding='utf-8') as f:\n" +
        "            f.write(header + code)\n" +
        "        print('Script saved: %s' % full_path)\n" +
        "        print('Reload scripts in Ghidra: Script Manager > Refresh (green arrow)')\n" +
        "        return full_path\n" +
        "\n" +
        "    def load_script(self, name):\n" +
        "        '''Read and return the content of a script from the scripts directory.\n" +
        "        Use to review or edit-then-save existing scripts.'''\n" +
        "        import os\n" +
        "        if not name.endswith('.py'): name += '.py'\n" +
        "        path = os.path.join(self._scripts_dir(), name)\n" +
        "        if not os.path.exists(path): return 'Script not found: %s' % path\n" +
        "        with open(path, 'r', encoding='utf-8') as f: return f.read()\n" +
        "\n" +
        "    def list_scripts(self, pattern=None):\n" +
        "        '''List scripts in the Ghidra scripts directory.\n" +
        "        pattern: optional substring filter on filename.\n" +
        "        Returns list of {name, path, category, description} dicts.'''\n" +
        "        import os, re as _re\n" +
        "        scripts_dir = self._scripts_dir()\n" +
        "        result = []\n" +
        "        if not os.path.isdir(scripts_dir): return []\n" +
        "        for fname in sorted(os.listdir(scripts_dir)):\n" +
        "            if not fname.endswith('.py'): continue\n" +
        "            if pattern and pattern.lower() not in fname.lower(): continue\n" +
        "            fpath = os.path.join(scripts_dir, fname)\n" +
        "            cat = desc = ''\n" +
        "            try:\n" +
        "                with open(fpath, 'r', encoding='utf-8', errors='replace') as f:\n" +
        "                    for line in f:\n" +
        "                        if not line.startswith('#'): break\n" +
        "                        m = _re.match(r'#\\s*@category\\s+(.*)', line)\n" +
        "                        if m: cat = m.group(1).strip()\n" +
        "                        m = _re.match(r'#\\s*@description\\s+(.*)', line)\n" +
        "                        if m: desc = m.group(1).strip()\n" +
        "            except: pass\n" +
        "            result.append({'name': fname, 'path': fpath, 'category': cat, 'description': desc})\n" +
        "        return result\n" +
        "\n" +
        "    def run_script(self, name):\n" +
        "        '''Execute an existing script from the scripts directory in the current Ghidra context.\n" +
        "        Equivalent to running it from Script Manager but called from MCP.\n" +
        "        Output is captured and returned.'''\n" +
        "        import os, io\n" +
        "        from ghidra.app.script import GhidraScriptUtil\n" +
        "        from generic.jar import ResourceFile\n" +
        "        from ghidra.app.script import GhidraState\n" +
        "        from ghidra.app.script import ScriptControls\n" +
        "        from ghidra.util.task import TaskMonitor\n" +
        "        if not name.endswith('.py'): name += '.py'\n" +
        "        path = os.path.join(self._scripts_dir(), name)\n" +
        "        if not os.path.exists(path): return 'Script not found: %s' % path\n" +
        "        resource = ResourceFile(java.io.File(path))\n" +
        "        provider = GhidraScriptUtil.getProvider(resource)\n" +
        "        if not provider: return 'No script provider for: %s' % name\n" +
        "        import java.io.PrintWriter as PrintWriter\n" +
        "        import java.io.StringWriter as StringWriter\n" +
        "        sw = StringWriter()\n" +
        "        pw = PrintWriter(sw)\n" +
        "        script_instance = provider.getScriptInstance(resource, pw)\n" +
        "        script_instance.execute(state, ScriptControls(pw, pw, TaskMonitor.DUMMY))\n" +
        "        return sw.toString() or 'Script ran with no output'\n" +
        "\n" +
        "reng = REngHelpers()\n\n";

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
            "  Workflow: call dbg.status() first; if connected=False use `debugger` tool to diagnose the session.\n\n" +
            "Reverse Engineering Prelude Active (call via 'reng.method') — works with or without live debugger:\n" +
            "  Address conv:  reng.image_base() → runtime base inferred from debugger thread names\n" +
            "                 reng.to_rt(static_addr) / reng.to_static(rt_addr) → ASLR conversion\n" +
            "  RTTI:          reng.rtti(rt_obj_ptr) → MSVC x64 class name (reads vtable[-8]→COL→TypeDescriptor)\n" +
            "  Struct explorer (ReClass.NET-style):\n" +
            "                 reng.explore(rt_addr, size=256) → field table: offset/hex/ptr-type/int/float/note\n" +
            "                   Auto-identifies vtable, fn-ptrs, sub-object RTTI, nulls, small ints, floats\n" +
            "                 reng.read_struct(rt_addr, {'health':(0x54,'f32'), 'pos_x':(0xD0,'f32')}) → {name:val}\n" +
            "                   types: u8/u16/u32/u64/i8/i16/i32/i64/f32/f64/ptr/cstr/wstr\n" +
            "  Struct authoring:\n" +
            "                 reng.define_struct('Actor', {'formID':(0x18,4,'FormID'), 'pos':(0xD0,4,'X pos')}) → DataType\n" +
            "                   If struct exists: existing NAMED fields are preserved, new fields merged in\n" +
            "                   Call with fields={} to inspect current definition\n" +
            "  RTTI/vtable scanner (static, fast):\n" +
            "                 reng.scan_vtables() → {vtable_static_addr: class_name} — scans .rdata for all MSVC vtables\n" +
            "                 reng.rename_vfuncs() → renames FUN_* into ClassName::vfunc_N namespaces\n" +
            "                   dry_run=True to preview count without modifying\n" +
            "  Standard RE workflows:\n" +
            "  ReClass.NET struct experimentation workflow:\n" +
            "    1. Identify:    reng.rtti(rt_ptr) → 'PlayerCharacter'\n" +
            "    2. Explore:     reng.explore(rt_ptr) → auto-interpreted field table\n" +
            "    3. Drill down:  reng.follow(rt_ptr, 0x20) → explore sub-object at ptr offset 0x20\n" +
            "    4. Re-interp:   reng.as_array(rt_ptr, 0xD0, 3, 'f32') → [x, y, z] floats at offset\n" +
            "    5. Diff:        reng.diff(ptr_a, ptr_b) → fields that differ between two instances\n" +
            "                     KEY: find two Actors, damage one, diff → health/stamina offsets revealed\n" +
            "    6. Record:      reng.define_struct('Actor', {'health':(0x54,4,'hp f32'), 'pos_x':(0xD0,4,'X')})\n" +
            "                     Existing named fields are PRESERVED; new fields are merged in\n" +
            "    7. Inspect existing: reng.define_struct('Actor', {}) → show current definition\n" +
            "  RTTI vs vfunc names (important distinction):\n" +
            "    - RTTI stores: class NAME and full INHERITANCE CHAIN (not vfunc names)\n" +
            "    - reng.class_hierarchy(rt_ptr) → [{class, offset, index}] ordered base→derived\n" +
            "    - reng.vtable_methods(rt_ptr) → [{slot, rt, static, name, named}] — function addresses\n" +
            "      'name' comes from Ghidra analysis. Already-named fns show their real name.\n" +
            "      Unnamed FUN_* slots → use dbg.set_breakpoint + observe to identify them.\n" +
            "    - To get names: import SKSE/CommonLibSSE headers into Ghidra, then vtable_methods()\n" +
            "      shows propagated names; reng.rename_vfuncs() assigns ClassName::vfunc_N for rest\n" +
            "  Bulk operations:\n" +
            "    5. Bulk rename: reng.rename_vfuncs(reng.scan_vtables())\n" +
            "    6. Resolve virt calls: breakpoint on `call [rax+N]`, read RCX → reng.rtti(RCX),\n" +
            "                           slot = N/8, reng.vtable_methods(RCX)[slot] → exact function\n" +
            "  Script management (generate persistent RE tools for Ghidra Script Manager):\n" +
            "    reng.save_script('FindActors.py', code, category='MCP', description='...')\n" +
            "      Writes to ~/ghidra_scripts/. Prepends @category/@description metadata.\n" +
            "      Script appears in Ghidra Script Manager after Refresh (green arrow).\n" +
            "      Scripts must use GhidraScript globals: currentProgram, monitor, state, etc.\n" +
            "    reng.list_scripts(pattern=None) → [{name, path, category, description}]\n" +
            "    reng.load_script('name.py')     → script source for review/editing\n" +
            "    reng.run_script('name.py')      → execute existing script, capture output\n" +
            "    Workflow: prototype logic in eval_python, save working code with save_script,\n" +
            "      result is a reusable Ghidra tool for future RE sessions.";
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
