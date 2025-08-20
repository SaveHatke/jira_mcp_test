# company_llm.py (v2 - 422-hardened)
import json
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple, Sequence, Union
import httpx
from pydantic import PrivateAttr, Field, BaseModel
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage, AIMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.tools import BaseTool
# ------------------------ Utilities ------------------------

def _bound_tool_index(bound_tools: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Map tool name -> tool spec from self._bound_tools (created in bind_tools)."""
    idx = {}
    for t in bound_tools or []:
        if t.get("type") == "function":
            f = t.get("function", {})
            name = f.get("name")
            if isinstance(name, str) and name:
                idx[name] = f
    return idx

def _required_fields_from_tool_spec(func_spec: Dict[str, Any]) -> List[str]:
    """Extract 'required' from a tool's Pydantic schema (or dict schema)."""
    params = func_spec.get("parameters") or {}
    req = params.get("required") or []
    # tolerate weird shapes
    if not isinstance(req, list):
        return []
    return [str(x) for x in req if isinstance(x, (str, int))]

def _load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
def _redact_headers(headers: Dict[str, Any]) -> Dict[str, Any]:
    return {
        k: ("<redacted>" if k.lower() in {"authorization", "cookie", "x-api-key"} else v)
        for k, v in headers.items()
    }
def _safe_json(obj: Any) -> str:
    try:
        return json.dumps(obj, indent=2, ensure_ascii=False)
    except Exception:
        try:
            return json.dumps(str(obj))
        except Exception:
            return "<unserializable>"
def _pick_last_user_and_history(messages: List[BaseMessage]) -> Tuple[str, str, Optional[str]]:
    user_query = ""
    history_lines = []
    system_instruction = None
    for m in messages:
        if isinstance(m, SystemMessage) and system_instruction is None:
            system_instruction = m.content
        elif isinstance(m, HumanMessage):
            user_query = m.content  # last HumanMessage wins
            history_lines.append(f"USER: {m.content}")
        elif isinstance(m, AIMessage):
            history_lines.append(f"ASSISTANT: {m.content}")
    history_text = "\n".join(history_lines[:-1]) if len(history_lines) > 1 else ""
    return user_query, history_text, system_instruction
def _extract_by_path(obj: Any, path: str) -> Any:
    cur = obj
    for part in path.split("."):
        if "[" in part and "]" in part:
            name, idx = part.split("[", 1)
            idx = int(idx.rstrip("]"))
            if name:
                cur = cur.get(name) if isinstance(cur, dict) else getattr(cur, name)
            cur = cur[idx]
        else:
            cur = cur.get(part) if isinstance(cur, dict) else getattr(cur, part)
    return cur
def _coerce_json_from_text(text: str) -> Optional[dict]:
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        pass
    lowered = text.strip()
    fences = ["```json", "```JSON", "```"]
    for fence in fences:
        if lowered.startswith(fence):
            try:
                body = lowered[len(fence):]
                end = body.rfind("```")
                if end != -1:
                    body = body[:end]
                return json.loads(body.strip())
            except Exception:
                continue
    return None
def _prune_empty(d: Any) -> Any:
    """Remove keys with None or empty values; leave False/0 intact."""
    if isinstance(d, dict):
        return {k: _prune_empty(v) for k, v in d.items() if v not in (None, "", [], {})}
    if isinstance(d, list):
        return [ _prune_empty(x) for x in d if x not in (None, "", [], {}) ]
    return d
# ------------------------ LLM Wrapper ------------------------
class CompanyChatLLM(BaseChatModel):
    """
    LangChain-compatible wrapper for your company LLM.
    - Does NOT require native tool-calling on the server.
    - Can optionally synthesize tool calls from a strict JSON envelope.
    - 422-friendly: configurable schema remaps, history format, parameter renames,
      optional payload pruning, and optional omission of tool schemas in payload.
    """
    # ---------- Pydantic fields ----------
    endpoint: str
    headers_json_path: str
    payload_json_path: str
    response_path: str  # where to find the model's textual output in HTTP response
    parameters: Dict[str, Any] = Field(default_factory=dict)
    request_timeout_s: int = 45
    max_retries: int = 2
    debug_log: bool = True
    request_id_header: str = "X-Request-Id"
    # Compatibility knobs (avoid 422s)
    include_tools_in_payload: bool = True  # many backends reject unknown keys
    prune_empty_keys: bool = True
    # compat: runtime schema flex:
    # {
    #   "field_map": {"query":"query","history":"history","systemInstruction":"systemInstruction"},
    #   "history_mode": "string" | "array_openai" | "array_flat",
    #   "parameters_key": "parameters" | "generationConfig" | "config",
    #   "param_renames": {"max_tokens":"maxTokens","top_p":"topP"},
    # }
    compat: Dict[str, Any] = Field(default_factory=dict)
    # ---------- Private attributes ----------
    _base_headers: Dict[str, Any] = PrivateAttr(default_factory=dict)
    _payload_template: Dict[str, Any] = PrivateAttr(default_factory=dict)
    _bound_tools: List[Dict[str, Any]] = PrivateAttr(default_factory=list)
    def __init__(self, **data: Any):
        super().__init__(**data)
        self._base_headers = _load_json(self.headers_json_path)
        self._payload_template = _load_json(self.payload_json_path)
        # defaults for compat
        self._field_map = {
            "query": "query",
            "history": "history",
            "systemInstruction": "systemInstruction",
        }
        self._history_mode = "string"  # or: array_openai, array_flat
        self._parameters_key = "parameters"
        self._param_renames = {}
        c = self.compat or {}
        self._field_map.update(c.get("field_map", {}))
        self._history_mode = c.get("history_mode", self._history_mode)
        self._parameters_key = c.get("parameters_key", self._parameters_key)
        self._param_renames = c.get("param_renames", {})
    @property
    def _llm_type(self) -> str:
        return "company_chat_llm"
    # -------- Tool binding (optional; simulated) --------
    def bind_tools(self, tools: Sequence[Union[BaseTool, dict]], **kwargs):
        schemas: List[Dict[str, Any]] = []
        for t in tools:
            if isinstance(t, dict):
                schemas.append(t); continue
            try:
                params_schema = (
                    t.args_schema.schema()
                    if getattr(t, "args_schema", None) and hasattr(t.args_schema, "schema")
                    else getattr(getattr(t, "args_schema", None), "model_json_schema", lambda: {"type": "object", "properties": {}, "required": []})()
                )
            except Exception:
                params_schema = {"type": "object", "properties": {}, "required": []}
            schemas.append({
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": getattr(t, "description", "") or "",
                    "parameters": params_schema
                }
            })
        new = self.copy(deep=True)
        new._bound_tools = schemas
        if self.debug_log:
            print("[CompanyChatLLM] Tools bound:", _safe_json(new._bound_tools))
        return new
    # -------- Prompt scaffolding (JSON envelope) --------
    def _tools_instruction_block(self) -> str:
        if not self._bound_tools:
            return (
                "You have NO tools available.\n"
                "Return only JSON:\n"
                "{ \"mode\": \"final\", \"final\": \"<answer>\" }\n"
                "No extra keys. No markdown outside JSON."
            )
        lines = ["You can call exactly one of the following tools at a time:"]
        for t in self._bound_tools:
            if t.get("type") == "function":
                f = t.get("function", {})
                lines.append(f'- {f.get("name")}: {f.get("description","").strip()}')
        lines += [
            "",
            "Return ONLY one of the following JSON envelopes (no prose outside JSON):",
            "1) To call a tool:",
            "{ \"mode\": \"tool\", \"tool\": \"<tool_name>\", \"args\": { ... } }",
            "2) If no tool is needed:",
            "{ \"mode\": \"final\", \"final\": \"<assistant answer text>\" }",
        ]
        lines += [
            "",
            "When the user asks to create work, choose the correct tool and fill args:",
            "- jira_create_story args example:",
            "  {\"project_key\":\"ABC\",\"summary\":\"Login page validation\",\"description\":\"As a user...\",\"acceptance_criteria\":[\"...\"],\"estimate\":3,\"labels\":[\"frontend\",\"auth\"]}",
            "- jira_create_task args example:",
            "  {\"project_key\":\"ABC\",\"summary\":\"Instrument metrics\",\"description\":\"...\",\"estimate\":2}",
            "",
            "If required fields are missing, return mode=\"final\" with a compact clarifying question."
            ]

        return "\n".join(lines)
    def _augment_system_instruction(self, existing: Optional[str]) -> str:
        prefix = (
            "You are an assistant for Jira automation. Follow strictly:\n"
            "- Think silently; do not reveal chain-of-thought.\n"
            "- Output ONLY the JSON envelope specified below.\n"
            "- If args are unclear, return mode=\"final\" and ask a clarifying question.\n"
        )
        block = self._tools_instruction_block()
        merged = (existing or "").strip()
        return f"{prefix}\n\n{block}\n\n{merged}" if merged else f"{prefix}\n\n{block}"
    # -------- Payload building --------
    
    def _history_as(self, messages: List[BaseMessage], history_text: str) -> Any:
        """
        Build history in the selected mode, including ToolMessage and assistant tool calls.
        Modes:
        - "string": plain text transcript (SYSTEM/USER/ASSISTANT/TOOL[...] lines)
        - "array_openai": list of {role, content, ...}, with 'tool' role entries
        - "array_flat": list[str] like the string mode but split per line
        """
        mode = self._history_mode
        # --- STRING MODE ---
        if mode == "string":
            lines: List[str] = []
            for m in messages:
                if isinstance(m, SystemMessage):
                    lines.append(f"SYSTEM: {m.content}")
                elif isinstance(m, HumanMessage):
                    lines.append(f"USER: {m.content}")
                elif isinstance(m, AIMessage):
                    # Preserve assistant tool calls for traceability
                    tc = getattr(m, "tool_calls", None) or (getattr(m, "additional_kwargs", {}) or {}).get("tool_calls")
                    if tc:
                        try:
                            lines.append("ASSISTANT_TOOL_CALLS: " + json.dumps(tc, ensure_ascii=False))
                        except Exception:
                            lines.append(f"ASSISTANT_TOOL_CALLS: {tc}")
                    if m.content:
                        lines.append(f"ASSISTANT: {m.content}")
                elif isinstance(m, ToolMessage):
                    # Include tool output
                    tname = getattr(m, "tool", getattr(m, "name", "unknown_tool"))
                    content = m.content
                    if not isinstance(content, str):
                        try:
                            content = json.dumps(content, ensure_ascii=False)
                        except Exception:
                            content = str(content)
                    lines.append(f"TOOL[{tname}]: {content}")
            return "\n".join(lines)
        # --- OPENAI-STYLE ARRAY MODE ---
        if mode == "array_openai":
            arr: List[Dict[str, Any]] = []
            for m in messages:
                if isinstance(m, SystemMessage):
                    arr.append({"role": "system", "content": m.content})
                elif isinstance(m, HumanMessage):
                    arr.append({"role": "user", "content": m.content})
                elif isinstance(m, AIMessage):
                    entry: Dict[str, Any] = {"role": "assistant", "content": m.content or ""}
                    # Mirror OpenAI tool_calls if present
                    ak = (getattr(m, "additional_kwargs", {}) or {})
                    if "tool_calls" in ak and ak["tool_calls"]:
                        entry["tool_calls"] = ak["tool_calls"]
                    arr.append(entry)
                elif isinstance(m, ToolMessage):
                    # Represent tool output using 'tool' role (OpenAI style)
                    tname = getattr(m, "tool", getattr(m, "name", "unknown_tool"))
                    content = m.content
                    if not isinstance(content, str):
                        try:
                            content = json.dumps(content, ensure_ascii=False)
                        except Exception:
                            content = str(content)
                    tool_entry: Dict[str, Any] = {
                        "role": "tool",
                        "content": content,
                        "name": tname
                    }
                    # Include call id if available (helps some runtimes stitch messages)
                    tcid = getattr(m, "tool_call_id", None)
                    if tcid:
                        tool_entry["tool_call_id"] = tcid
                    arr.append(tool_entry)
            return arr
        # --- FLAT ARRAY MODE (strings) ---
        if mode == "array_flat":
            arr: List[str] = []
            for m in messages:
                if isinstance(m, SystemMessage):
                    arr.append(f"SYSTEM: {m.content}")
                elif isinstance(m, HumanMessage):
                    arr.append(f"USER: {m.content}")
                elif isinstance(m, AIMessage):
                    tc = getattr(m, "tool_calls", None) or (getattr(m, "additional_kwargs", {}) or {}).get("tool_calls")
                    if tc:
                        try:
                            arr.append("ASSISTANT_TOOL_CALLS: " + json.dumps(tc, ensure_ascii=False))
                        except Exception:
                            arr.append(f"ASSISTANT_TOOL_CALLS: {tc}")
                    if m.content:
                        arr.append(f"ASSISTANT: {m.content}")
                elif isinstance(m, ToolMessage):
                    tname = getattr(m, "tool", getattr(m, "name", "unknown_tool"))
                    content = m.content
                    if not isinstance(content, str):
                        try:
                            content = json.dumps(content, ensure_ascii=False)
                        except Exception:
                            content = str(content)
                    arr.append(f"TOOL[{tname}]: {content}")
            return arr
        # Fallback to provided text for unknown modes
        return history_text


    def _apply_param_renames(self, params: Dict[str, Any]) -> Dict[str, Any]:
        if not self._param_renames:
            return params
        renamed = {}
        for k, v in params.items():
            renamed[self._param_renames.get(k, k)] = v
        return renamed
    def _build_payload(self, messages: List[BaseMessage]) -> Dict[str, Any]:
        user_query, history_text, system_instruction = _pick_last_user_and_history(messages)
        payload = json.loads(json.dumps(self._payload_template))  # deep copy
        final_sys = self._augment_system_instruction(system_instruction)
        # Remappable field names
        q_key = self._field_map.get("query", "query")
        h_key = self._field_map.get("history", "history")
        s_key = self._field_map.get("systemInstruction", "systemInstruction")
        # Populate (only if keys exist OR create them if not present)
        payload[q_key] = user_query
        payload[h_key] = self._history_as(messages, history_text)
        payload[s_key] = final_sys
        # Parameters block (with optional renames and key override)
        params_key = self._parameters_key
        merged_params = dict(payload.get(params_key, {}))
        for k, v in (self.parameters or {}).items():
            merged_params[k] = v
        payload[params_key] = self._apply_param_renames(merged_params)
        # Optional: include schemas (OFF by default to avoid 422)
        if self.include_tools_in_payload and self._bound_tools:
            payload["tools"] = self._bound_tools
            payload.setdefault("tool_choice", "auto")
        # if self.prune_empty_keys:
        #     payload = _prune_empty(payload)
        if self.debug_log:
            print("[CompanyChatLLM] _build_payload ->")
            print("  field_map:", _safe_json(self._field_map))
            print("  history_mode:", self._history_mode)
            print("  parameters_key:", params_key)
            print("  payload:", _safe_json(payload))
        return payload
    # -------- HTTP --------
    def _http_post(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        POST to the company LLM endpoint, mirroring Postman's http.client behavior:
        - raw JSON body (content=)
        - no automatic/default headers
        - HTTP/1.1 (http2=False)
        - logs request/response regardless of debug flag
        """
        # Load headers exactly as you have in headers.json
        headers = _load_json(self.headers_json_path)
        # Build raw JSON body (do NOT use json=payload here)
        body = json.dumps(payload, ensure_ascii=False)
        # Simple redactor for sensitive headers (print regardless of debug)
        def _redact(h: dict) -> dict:
            out = {}
            for k, v in (h or {}).items():
                kl = str(k).lower()
                if kl in ("cookie", "authorization", "x-csrf-token"):
                    out[k] = f"<redacted:{len(str(v))} chars>"
                else:
                    out[k] = v
            return out
        # Request preview (always print to help diagnose 401s)
        print("[CompanyChatLLM] POST", self.endpoint)
        print("[CompanyChatLLM] Headers:", json.dumps(_redact(headers), ensure_ascii=False, indent=2))
        print("[CompanyChatLLM] Body:", body[:2000])
        last_exc = None
        for attempt in range(1, self.max_retries + 1):
            try:
                # Make httpx behave like Postman's http.client export
                with httpx.Client(
                    timeout=self.request_timeout_s,
                    verify=True,              # set False if your Postman run ignored TLS
                    follow_redirects=True,
                    http2=False,              # force HTTP/1.1 like http.client
                    headers={}                # IMPORTANT: prevent default headers
                ) as client:
                    # Build explicit Request so we can inspect the *actual* wire headers
                    req = client.build_request(
                        "POST",
                        self.endpoint,
                        headers=headers,       # exactly what you have in headers.json
                        content=body           # raw JSON string
                    )
                    # Show on-wire headers (names/values after httpx normalization)
                    try:
                        final_hdrs = {k.decode(): v.decode() for k, v in req.headers.raw}
                    except Exception:
                        final_hdrs = dict(req.headers)
                    print("[CompanyChatLLM] Final Request Headers:", json.dumps(_redact(final_hdrs), ensure_ascii=False, indent=2))
                    resp = client.send(req)
                # Response preview
                print("[CompanyChatLLM] Status:", resp.status_code, resp.reason_phrase)
                try:
                    resp_json = resp.json()
                    print("[CompanyChatLLM] Response JSON:", json.dumps(resp_json, ensure_ascii=False)[:2000])
                except Exception:
                    print("[CompanyChatLLM] Response Text:", (resp.text or "")[:2000])
                # Raise for non-2xx to trigger retry
                resp.raise_for_status()
                # Return JSON if ok
                try:
                    return resp.json()
                except Exception as je:
                    raise RuntimeError(f"Response not JSON: {je}") from je
            except Exception as e:
                last_exc = e
                if attempt >= self.max_retries:
                    break
                print(f"[CompanyChatLLM] Attempt {attempt} failed: {e}. Retrying...")
                time.sleep(0.8 * attempt)
        # Exhausted retries
        raise last_exc if last_exc else RuntimeError("Unknown HTTP error")

    # -------- Output parsing --------
    
    def _parse_model_output(self, data: Dict[str, Any]) -> Tuple[Optional[str], Optional[List[Dict[str, Any]]]]:
        # 1) get the raw textual content
        content = None
        if self.response_path:
            try:
                content = _extract_by_path(data, self.response_path)
            except Exception:
                content = None
        if content is None:
            for path in ["choices[0].message.content", "text", "answer", "data.answer", "output"]:
                try:
                    content = _extract_by_path(data, path)
                    if content:
                        break
                except Exception:
                    continue
        if self.debug_log:
            print("[CompanyChatLLM] _parse_model_output content:", repr(content)[:800])
        # 2) try to parse the model's JSON envelope
        envelope = _coerce_json_from_text(content if isinstance(content, str) else "")
        if self.debug_log:
            print("[CompanyChatLLM] Parsed envelope:", _safe_json(envelope))
        # 3) handle structured envelopes
        if isinstance(envelope, dict):
            mode = envelope.get("mode")
            # ---- tool path ----
            if mode == "tool":
                tool_name = envelope.get("tool") or ""
                args = envelope.get("args", {}) or {}
                if not isinstance(args, dict):
                    try:
                        args = json.loads(args) if isinstance(args, str) else dict(args)
                    except Exception:
                        args = {}
                # validate against bound tools
                tool_map = _bound_tool_index(self._bound_tools)
                func_spec = tool_map.get(tool_name)
                if not func_spec:
                    # Unknown tool -> ask user to pick a valid one (break the loop)
                    valid = ", ".join(sorted(tool_map.keys())) or "<no tools bound>"
                    msg = f"I don't recognize the tool '{tool_name}'. Available tools are: {valid}. Which one should I use?"
                    return msg, None
                # check required args
                required = _required_fields_from_tool_spec(func_spec)
                missing = [k for k in required if k not in args or args[k] in (None, "", [], {})]
                if missing:
                    need = ", ".join(missing)
                    msg = f"I can call `{tool_name}`, but I still need: {need}. Please provide these field(s)."
                    return msg, None  # <-- final text, no tool_calls => stops loop
                # valid tool call
                call_id = f"call_{uuid.uuid4().hex[:12]}"
                tool_calls = [{
                    "id": call_id,
                    "name": tool_name,
                    "args": args
                }]
                if self.debug_log:
                    print("[CompanyChatLLM] Synthesized tool_calls:", _safe_json(tool_calls))
                return None, tool_calls
            # ---- final answer path ----
            if mode == "final":
                final_text = envelope.get("final", "")
                if not isinstance(final_text, str):
                    try:
                        final_text = json.dumps(final_text, ensure_ascii=False)
                    except Exception:
                        final_text = str(final_text)
                return final_text, None
        # 4) fallback: treat content as plain text
        if isinstance(content, str):
            return content, None
        # last resort: stringify response
        return _safe_json(data), None


    # -------- LangChain hook --------
    def _generate(
            self,
            messages: List[BaseMessage],
            stop: Optional[List[str]] = None,
            run_manager: Optional[CallbackManagerForLLMRun] = None,
            **kwargs: Any,
        ) -> ChatResult:
        # Build payload and call your company LLM
        payload = self._build_payload(messages)
        data = self._http_post(payload)
        # Parse model output -> (assistant_text, tool_calls)
        assistant_text, tool_calls = self._parse_model_output(data)
        if tool_calls:
            # --- LangChain (LC) simplified tool_calls format ---
            # Normalize to ensure id/name/args are present
            lc_calls = []
            for c in tool_calls:
                lc_calls.append({
                    "id": c.get("id") or f"call_{uuid.uuid4().hex[:12]}",
                    "name": c.get("name"),
                    "args": c.get("args", {}) or {},
                })
            ai = AIMessage(content="", tool_calls=lc_calls)
            # --- OpenAI-style tool_calls in additional_kwargs ---
            oai_calls = []
            for c in lc_calls:
                try:
                    args_str = json.dumps(c["args"], ensure_ascii=False)
                except Exception:
                    args_str = "{}"
                oai_calls.append({
                    "id": c["id"],
                    "type": "function",
                    "function": {
                        "name": c["name"],
                        "arguments": args_str
                    }
                })
            ak = dict(getattr(ai, "additional_kwargs", {}) or {})
            ak["tool_calls"] = oai_calls
            # Legacy single-call compatibility (some nodes look for this)
            if len(oai_calls) == 1:
                ak["function_call"] = oai_calls[0]["function"]
            ai.additional_kwargs = ak
        else:
            # No tool call -> plain assistant message
            ai = AIMessage(content=assistant_text or "")
        if self.debug_log:
            print("[CompanyChatLLM] _generate ->")
            print("  assistant_text:", repr(assistant_text)[:500])
            # Log both LC and OpenAI-style shapes for debugging
            try:
                print("  tool_calls (LC):", _safe_json(getattr(ai, "tool_calls", None)))
            except Exception:
                print("  tool_calls (LC):", getattr(ai, "tool_calls", None))
            try:
                print("  addl_kwargs.tool_calls (OpenAI):",
                    _safe_json(getattr(ai, "additional_kwargs", {}).get("tool_calls")))
            except Exception:
                print("  addl_kwargs.tool_calls (OpenAI):",
                    getattr(ai, "additional_kwargs", {}).get("tool_calls"))
        return ChatResult(generations=[ChatGeneration(message=ai)],
                        llm_output={"raw_response": data})
