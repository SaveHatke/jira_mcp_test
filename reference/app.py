# app.py (enhanced event tracing & message inspection)
import asyncio
import json
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
from langchain_core.messages import HumanMessage, AIMessage, ToolMessage
from tachyon import CompanyChatLLM
from langgraph.checkpoint.memory import MemorySaver
def load_config():
    with open("config.json", "r") as file:
        return json.load(file)
config = load_config()
def make_llm_from_config():
    c = config["tachyon"]
    return CompanyChatLLM(
        endpoint=c["endpoint"],
        headers_json_path=c["headers_json_path"],
        payload_json_path=c["payload_json_path"],
        response_path=c.get("response_path", "answer"),
        request_timeout_s=c.get("request_timeout_s", 45),
        max_retries=c.get("max_retries", 2),
        debug_log=c.get("debug_log", True),
        include_tools_in_payload=True,   # keep this ON while debugging
    )
async def test_jira_agent():
    print("Testing JIRA MCP Agent...\n")
    client = MultiServerMCPClient({
        "mcp-atlassian": {
            "command": "mcp-atlassian",
            "args": ["--transport", "stdio"],
            "env": {
                "JIRA_URL": config.get("jira_url"),
                "JIRA_PERSONAL_TOKEN": config.get("jira_api_token"),
                "JIRA_SSL_VERIFY": "false"
            },
            "transport": "stdio",
        }
    })
    try:
        tools = await client.get_tools()
        print(f"Discovered {len(tools)} tools: {[t.name for t in tools]}\n")
        llm = make_llm_from_config().bind_tools(tools)
        agent = create_react_agent(
            model=llm,
            tools=tools,
            checkpointer=MemorySaver()
        )
        query = "give me tickets assigned to K108919"
        print(f"Invoking Agent with query: {query}\n")
        cfg = {
            "recursion_limit": 4,  # use 8 for debugging; you can drop to 4 later
            "configurable": {"thread_id": "debug-run-1"}
        }
        # --- STREAM EVENTS ---
        async for ev in agent.astream_events({"messages": [HumanMessage(content=query)]},
                                             config=cfg, version="v1"):
            et = ev.get("event")
            nm = ev.get("name", "")
            if et == "on_chain_start":
                print(f"START {nm}")
            elif et == "on_chain_end":
                print(f"END   {nm}")
            elif et == "on_tool_start":
                print(f"TOOL START: {nm}")
            elif et == "on_tool_end":
                print(f"TOOL END  : {nm}")
            elif et == "on_chat_model_start":
                print("LLM START")
            elif et == "on_chat_model_end":
                print("LLM END")
                # Inspect the assistant message the model just produced (if present)
                data = ev.get("data", {})
                try:
                    outs = data.get("output", {})
                    # Some versions put message(s) under "generations", others under "message"
                    msg = None
                    gens = outs.get("generations") or []
                    if gens and isinstance(gens, list):
                        # generations is a list[ChatGeneration]; extract message if present
                        gen0 = gens[0]
                        msg = gen0.get("message") if isinstance(gen0, dict) else None
                    if not msg:
                        msg = outs.get("message")
                    if msg:
                        # Print tool_calls from both places
                        ak = (msg.get("additional_kwargs") or {})
                        print("   ├─ assistant.content:", repr(msg.get("content"))[:200])
                        print("   ├─ assistant.tool_calls (LC):", msg.get("tool_calls"))
                        print("   └─ assistant.additional_kwargs.tool_calls (OpenAI):", ak.get("tool_calls"))
                    else:
                        print("   (no assistant message in event payload)")
                except Exception as ex:
                    print(f"   (could not inspect assistant message: {ex})")
        # --- RUN ONCE MORE TO GET FINAL OUTPUT ---
        response = await agent.ainvoke({"messages": [HumanMessage(content=query)]}, config=cfg)
        msgs = response["messages"]
        final = msgs[-1]
        print("\n--- FINAL STATE ---")
        # Print the last two messages to see if a tool was used
        for m in msgs[-3:]:
            role = m.__class__.__name__
            base = getattr(m, "content", "")
            print(f"[{role}] {str(base)[:300]}")
            if isinstance(m, AIMessage):
                print("   tool_calls (LC):", getattr(m, "tool_calls", None))
                print("   addl_kwargs.tool_calls (OpenAI):", getattr(m, "additional_kwargs", {}).get("tool_calls"))
            if isinstance(m, ToolMessage):
                print("   (tool output above)")
        print("\nAgent Response:\n", final.content)
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False
    finally:
        try:
            await client.aclose()
        except:
            pass
async def main():
    ok = await test_jira_agent()
    print("\nResult:", "Success" if ok else "Failed")
if __name__ == "__main__":
    asyncio.run(main())
