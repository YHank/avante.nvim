local Path = require("plenary.path")
local Utils = require("avante.utils")
local Providers = require("avante.providers")
local Claude = require("avante.providers.claude")
local HistoryMessage = require("avante.history.message")

local H = {}

---@class AvanteProviderFunctor
local M = {}

-- LLM-ORC paths
local llm_orc_config_dir = Path:new(vim.fn.expand("~/.config/llm-orc"))
local llm_orc_credentials_file = llm_orc_config_dir:joinpath("credentials.yaml")
local llm_orc_encryption_key_file = llm_orc_config_dir:joinpath(".encryption_key")

M.api_key_name = nil
M.tokenizer_id = "gpt-4o"
M.support_prompt_caching = true
M.role_map = {
  user = "user",
  assistant = "assistant",
}

-- Override parse_api_key to return nil (no API key needed for OAuth)
function M.parse_api_key()
  return nil
end

-- Use Claude's tool transformation
function M:transform_tool(tool)
  return Claude:transform_tool(tool)
end

function M:is_disable_stream() return false end

function M:parse_messages(opts)
  -- Same as before - reuse existing logic
  local messages = {}
  local provider_conf, _ = Providers.parse_config(self)

  -- context 메시지 수집 (선택된 코드와 일반 컨텍스트 분리)
  local context_content = ""
  local selected_code_content = ""
  local has_selected_code = false

  for _, message in ipairs(opts.messages) do
    if message.is_context then
      local content = message.content
      -- selected_code 태그 확인
      if content:match("<selected_code") then
        selected_code_content = content
        has_selected_code = true
      else
        if context_content ~= "" then
          context_content = context_content .. "\n\n"
        end
        context_content = context_content .. content
      end
    end
  end

  -- 강제로 .avanterules 지침 추가 (OAuth 제약 우회)
  local forced_instructions = [[
You are a highly skilled software engineer with extensive knowledge in many programming languages, frameworks, design patterns, and best practices.

Respect and use existing conventions, libraries, etc that are already present in the code base.

Make sure code comments are in English when generating them.

항상 ~/.config/nvim/agentic.avanterules 파일을 참고하세요.
항상 한글로 답변하세요.

====

IMPORTANT: 도구 사용 제한
- 사용자가 단순한 질문이나 코드 설명을 요청할 때는 도구를 사용하지 마세요.
- 파일 내용이 이미 컨텍스트로 제공된 경우 view 도구를 사용하지 마세요.
- 간단한 답변이 가능한 경우 직접 답변하세요.

====

선택된 코드 처리:
- 사용자가 코드 블록을 선택하고 <leader>ae를 누르면 <selected_code> 태그로 전달됩니다.
- 이 선택된 코드를 기반으로 작업해야 합니다.
- 선택된 코드가 있을 때는 해당 코드를 수정하거나 개선하는 것이 주요 목적입니다.
- 코드 수정 후에는 반드시 <code></code> 태그로 수정된 코드를 제공하세요.

====

TOOLS USAGE GUIDE

- You have access to tools, but only use them when absolutely necessary. If a tool is not required, respond as normal.
- Please DON'T be so aggressive in using tools, as many tasks can be better completed without tools.
- Files will be provided to you as context through <file> tag!
- Before using the `view` tool each time, always repeatedly check whether the file is already in the <file> tag. If it is already there, do not use the `view` tool, just read the file content directly from the <file> tag.
- If you use the `view` tool when file content is already provided in the <file> tag, you will be fired!
- Keep the `query` parameter of `rag_search` tool as concise as possible! Try to keep it within five English words!
- When attempting to modify a file that is not in the context, please first use the `ls` tool and `glob` tool to check if the file you want to modify exists, then use the `view` tool to read the file content. Don't modify blindly!
- When generating files, first use `ls` tool to read the directory structure, don't generate blindly!
- When creating files, first check if the directory exists. If it doesn't exist, create the directory before creating the file.
- Do not use the `run_python` tool to read or modify files!
- Do not use the `bash` tool to read or modify files!
- If you are provided with the `write_file` tool, there's no need to output your change suggestions, just directly use the `write_file` tool to complete the changes.

====

코드 수정 요청 시:
1. 수정된 코드는 반드시 <code></code> 태그로 감싸세요.
2. 백틱(```)은 사용하지 마세요.
3. 설명이나 주석, 줄 번호를 포함하지 마세요.
4. 원본 코드의 들여쓰기와 형식을 유지하세요.
5. 변경된 부분만 포함하세요.
6. <code> 태그 안에는 순수한 코드만 넣으세요.

예시:
<code>
def add(a, b):
    print(f"Adding {a} and {b}")
    return a + b
</code>

====

Memory is crucial, you must follow the instructions in <memory>!
]]

  local has_tool_use = false
  local first_user_msg_processed = false
  
  -- Claude.lua와 동일한 방식으로 처리 (context 메시지 제외)
  for _, message in ipairs(opts.messages) do
    -- context 메시지는 건너뛰기 (시스템 프롬프트에서 처리)
    if message.is_context then
      -- skip context messages
    else
      local content_items = message.content
      local message_content = {}

      if type(content_items) == "string" then
        if message.role == "assistant" then content_items = content_items:gsub("%s+$", "") end
        if content_items ~= "" then
          -- 첫 번째 user 메시지에 강제 지침 + context 추가
          if message.role == "user" and not first_user_msg_processed then
            local full_content = forced_instructions

            -- 선택된 코드가 있으면 최우선으로 추가
            if has_selected_code and selected_code_content ~= "" then
              full_content = full_content .. "\n\n=== 선택된 코드 (이 코드를 기반으로 작업하세요) ===\n" .. selected_code_content
              full_content = full_content .. "\n\n위의 선택된 코드를 수정하거나 개선한 결과를 <code></code> 태그로 제공하세요."
            end

            -- 일반 context가 있으면 추가 (토큰 제한 고려)
            if context_content and context_content ~= "" then
              -- context 길이 제한 (토큰 절약)
              local max_context_length = 15000  -- 선택 코드 공간 확보를 위해 줄임
              if #context_content > max_context_length then
                context_content = context_content:sub(1, max_context_length) .. "...\n(context truncated)"
              end
              full_content = full_content .. "\n\n=== 프로젝트 컨텍스트 ===\n" .. context_content
            end

            content_items = full_content .. "\n\n=== 사용자 요청 ===\n" .. content_items
            first_user_msg_processed = true
          elseif message.role == "user" and has_selected_code then
            -- 후속 사용자 메시지에도 선택 코드 참조 추가 (컨텍스트 유지)
            content_items = "참고: 이전에 선택한 코드를 기반으로 작업 중입니다.\n\n" .. content_items
          end
          table.insert(message_content, {
            type = "text",
            text = content_items,
          })
        end
      elseif type(content_items) == "table" then
        for _, item in ipairs(content_items) do
          if type(item) == "string" then
            if message.role == "assistant" then item = item:gsub("%s+$", "") end
            table.insert(message_content, { type = "text", text = item })
          elseif type(item) == "table" and item.type == "text" then
            table.insert(message_content, { type = "text", text = item.text })
          elseif type(item) == "table" and item.type == "image" then
            table.insert(message_content, { type = "image", source = item.source })
          elseif not provider_conf.disable_tools and type(item) == "table" and item.type == "tool_use" then
            has_tool_use = true
            table.insert(message_content, { type = "tool_use", name = item.name, id = item.id, input = item.input })
          elseif
            not provider_conf.disable_tools
            and type(item) == "table"
            and item.type == "tool_result"
            and has_tool_use
          then
            -- OAuth API는 is_user_declined 필드를 허용하지 않음
            table.insert(
              message_content,
              { type = "tool_result", tool_use_id = item.tool_use_id, content = item.content, is_error = item.is_error }
            )
          end
        end
      end

      if #message_content > 0 then
        table.insert(messages, {
          role = self.role_map[message.role] or message.role,
          content = message_content,
        })
      end
    end
  end

  return messages, context_content, has_selected_code
end

---@class ClaudeLLMOrcState
---@field oauth_token table?
M.state = nil

-- Decrypt LLM-ORC credentials (same as before)
local function decrypt_credentials()
  -- Check if files exist
  if not llm_orc_credentials_file:exists() or not llm_orc_encryption_key_file:exists() then
    return nil, "LLM-ORC credentials not found. Please run: llm-orc auth add anthropic-claude-pro-max"
  end

  -- Read encryption key
  local key_content = llm_orc_encryption_key_file:read()
  if not key_content then
    return nil, "Failed to read LLM-ORC encryption key"
  end

  -- Read encrypted credentials
  local encrypted_content = llm_orc_credentials_file:read()
  if not encrypted_content or encrypted_content == "" then
    return nil, "LLM-ORC credentials file is empty"
  end

  -- Try to decrypt using Python (since LLM-ORC uses Python's cryptography library)
  local python_script = string.format([[
import sys
import yaml
from cryptography.fernet import Fernet

try:
    key = b'%s'
    encrypted_data = b'%s'

    f = Fernet(key)
    decrypted = f.decrypt(encrypted_data)
    data = yaml.safe_load(decrypted.decode())

    if 'anthropic-claude-pro-max' in data:
        provider_data = data['anthropic-claude-pro-max']
        if provider_data.get('auth_method') == 'oauth':
            print(provider_data.get('access_token', ''))
            print(provider_data.get('refresh_token', ''))
            print(provider_data.get('expires_at', ''))
            print(provider_data.get('client_id', ''))
except Exception as e:
    print(f"ERROR: {str(e)}", file=sys.stderr)
    sys.exit(1)
]], key_content, encrypted_content)

  local result = vim.fn.system("python3 -c " .. vim.fn.shellescape(python_script))

  if vim.v.shell_error ~= 0 then
    return nil, "Failed to decrypt LLM-ORC credentials: " .. result
  end

  local lines = vim.split(result, "\n")
  if #lines < 4 then
    return nil, "Invalid LLM-ORC credentials format"
  end

  return {
    access_token = lines[1],
    refresh_token = lines[2],
    expires_at = tonumber(lines[3]) or 0,
    client_id = lines[4],
  }
end

function M:parse_curl_args(prompt_opts)
  -- Load OAuth token from LLM-ORC if not already loaded
  if not M.state or not M.state.oauth_token then
    local token_data, err = decrypt_credentials()
    if not token_data then
      error("Failed to load LLM-ORC credentials")
    end

    M.state = M.state or {}
    M.state.oauth_token = token_data
  end

  -- Check if token is expired and refresh if needed
  local now = os.time()
  if M.state.oauth_token.expires_at and M.state.oauth_token.expires_at <= now then
    -- 토큰이 만료되었으면 credentials를 다시 로드
    local token_data, err = decrypt_credentials()
    if not token_data then
      Utils.error("OAuth token expired and failed to reload: " .. (err or "unknown error"))
      error("Failed to reload expired OAuth token")
    end
    
    -- 새로운 토큰도 만료되었는지 확인
    if token_data.expires_at and token_data.expires_at <= now then
      Utils.error("LLM-ORC OAuth token is expired. Please refresh with: llm-orc auth add anthropic-claude-pro-max")
      error("OAuth token is expired")
    end
    
    M.state.oauth_token = token_data
    if vim.g.avante_debug then
      Utils.info("LLM-ORC: Reloaded OAuth token successfully")
    end
  end

  local provider_conf, request_body = Providers.parse_config(self)
  local disable_tools = provider_conf.disable_tools or false

  -- Build our own curl args instead of using Claude's
  local messages, context_content, has_selected_code = self:parse_messages(prompt_opts)

  -- OAuth requires EXACTLY this system prompt - cannot be modified
  local system_prompt = "You are Claude Code, Anthropic's official CLI for Claude."

  -- Tools 파싱 (claude.lua와 동일)
  local tools = {}
  if not disable_tools and prompt_opts.tools then
    for _, tool in ipairs(prompt_opts.tools) do
      table.insert(tools, self:transform_tool(tool))
    end
  end

  local curl_args = {
    url = Utils.url_join(provider_conf.endpoint, "/v1/messages"),
    proxy = provider_conf.proxy,
    insecure = provider_conf.allow_insecure,
    headers = {
      ["Content-Type"] = "application/json",
      ["anthropic-version"] = "2023-06-01",
      ["anthropic-beta"] = "oauth-2025-04-20",
      ["Authorization"] = "Bearer " .. M.state.oauth_token.access_token,
      ["User-Agent"] = "LLM-Orchestra/Python 0.3.0",
    },
    body = vim.tbl_deep_extend("force", {
      model = provider_conf.model,
      system = system_prompt,
      messages = messages,
      tools = tools,
      stream = true,
    }, request_body),
  }

  return curl_args
end

function M.is_env_set()
  return llm_orc_credentials_file:exists() and llm_orc_encryption_key_file:exists()
end

function M.setup()
  if not M.is_env_set() then
    return
  end

  -- Try to load credentials
  local token_data, err = decrypt_credentials()
  if not token_data then
    return
  end

  M.state = { oauth_token = token_data }

  require("avante.tokenizers").setup(M.tokenizer_id)
  vim.g.avante_claude_llm_orc_login = true
end

-- Error handling (same as before)
function M.on_error(result)
  if result.status == 429 then return end
  if not result.body then
    return Utils.error("API request failed with status " .. result.status, { once = true, title = "Avante" })
  end

  local ok, body = pcall(vim.json.decode, result.body)
  if not (ok and body and body.error) then
    return Utils.error("Failed to parse error response: " .. result.body:sub(1, 200), { once = true, title = "Avante" })
  end

  local error_msg = body.error.message
  local error_type = body.error.type

  if error_type == "authentication_error" and error_msg:match("x%-api%-key") then
    error_msg = "OAuth authentication failed. Please check your LLM-ORC credentials."
  end

  -- OAuth 시스템 프롬프트 변경 관련 에러 처리
  if error_type == "invalid_request_error" and (error_msg:match("system") or error_msg:match("Claude Code")) then
    Utils.warn("System prompt modification failed. Using fallback mode.")
    error_msg = "System prompt modification not supported. " .. error_msg
  end

  Utils.error(error_msg, { once = true, title = "Avante" })
end

-- OAuth 전용 파서: API 키 없이 동작하는 완전 자체 구현
function M:parse_response(ctx, data_stream, event_state, opts)
  if not data_stream or data_stream == "" then return end
  
  local ok, json = pcall(vim.json.decode, data_stream)
  if not ok then return end
  
  if ctx.content_blocks == nil then ctx.content_blocks = {} end
  
  if json.type == "message_start" then
    if json.message then
      ctx.usage = json.message.usage
    end
    
  elseif json.type == "content_block_start" then
    local content_block = json.content_block or {}
    ctx.content_blocks[json.index + 1] = content_block
    
    -- thinking 처리
    if content_block.type == "thinking" then
      if opts.on_chunk then opts.on_chunk("<think>\n") end
      if opts.on_messages_add then
        local msg = HistoryMessage:new("assistant", {
          type = "thinking",
          thinking = content_block.thinking or "",
          signature = content_block.signature,
        }, {
          state = "generating",
          turn_id = ctx.turn_id,
        })
        content_block.uuid = msg.uuid
        opts.on_messages_add({ msg })
      end
    -- text 처리 추가
    elseif content_block.type == "text" then
      content_block.text = content_block.text or ""
      if opts.on_messages_add then
        local msg = HistoryMessage:new("assistant", content_block.text or "", {
          state = "generating",
          turn_id = ctx.turn_id,
        })
        content_block.uuid = msg.uuid
        opts.on_messages_add({ msg })
      end
    -- tool_use 처리 추가
    elseif content_block.type == "tool_use" then
      content_block.input = content_block.input or {}
      if opts.on_messages_add then
        local msg = HistoryMessage:new("assistant", {
          type = "tool_use",
          name = content_block.name,
          id = content_block.id,
          input = content_block.input,
        }, {
          state = "generating",
          turn_id = ctx.turn_id,
        })
        content_block.uuid = msg.uuid
        opts.on_messages_add({ msg })
      end
    end
    
  elseif json.type == "content_block_delta" then
    local content_block = ctx.content_blocks[json.index + 1]
    if not content_block then return end
    
    -- thinking_delta 처리
    if json.delta and json.delta.type == "thinking_delta" then
      content_block.thinking = (content_block.thinking or "") .. json.delta.thinking
      if opts.on_chunk then opts.on_chunk(json.delta.thinking) end
      if opts.on_messages_add then
        local msg = HistoryMessage:new("assistant", {
          type = "thinking",
          thinking = content_block.thinking,
          signature = content_block.signature,
        }, {
          state = "generating",
          uuid = content_block.uuid,
          turn_id = ctx.turn_id,
        })
        opts.on_messages_add({ msg })
      end
    -- text_delta 처리 추가
    elseif json.delta and json.delta.type == "text_delta" and json.delta.text then
      content_block.text = (content_block.text or "") .. json.delta.text
      if opts.on_chunk then opts.on_chunk(json.delta.text) end
      if opts.on_messages_add then
        local msg = HistoryMessage:new("assistant", content_block.text, {
          state = "generating",
          uuid = content_block.uuid,
          turn_id = ctx.turn_id,
        })
        opts.on_messages_add({ msg })
      end
    -- input_json_delta 처리 추가 (tool_use의 input 파라미터)
    elseif json.delta and json.delta.type == "input_json_delta" and content_block.type == "tool_use" then
      local partial_json = json.delta.partial_json or ""
      content_block.input_json = (content_block.input_json or "") .. partial_json
      
      -- JSON 파싱 시도
      local ok, parsed_input = pcall(vim.json.decode, content_block.input_json)
      if ok then
        content_block.input = parsed_input
        if opts.on_messages_add then
          local msg = HistoryMessage:new("assistant", {
            type = "tool_use",
            name = content_block.name,
            id = content_block.id,
            input = content_block.input,
          }, {
            state = "generating",
            uuid = content_block.uuid,
            turn_id = ctx.turn_id,
          })
          opts.on_messages_add({ msg })
        end
      end
    end
    
  elseif json.type == "content_block_stop" then
    local content_block = ctx.content_blocks[json.index + 1]
    if content_block and content_block.type == "thinking" then
      if opts.on_chunk then
        local thinking_text = content_block.thinking or ""
        if thinking_text ~= "" and thinking_text:sub(-1) ~= "\n" then
          opts.on_chunk("\n</think>\n\n")
        else
          opts.on_chunk("</think>\n\n")
        end
      end
      if opts.on_messages_add then
        local msg = HistoryMessage:new("assistant", {
          type = "thinking",
          thinking = content_block.thinking,
          signature = content_block.signature,
        }, {
          state = "generated",
          uuid = content_block.uuid,
          turn_id = ctx.turn_id,
        })
        opts.on_messages_add({ msg })
      end
    elseif content_block and content_block.type == "text" then
      if opts.on_messages_add then
        local msg = HistoryMessage:new("assistant", content_block.text or "", {
          state = "generated",
          uuid = content_block.uuid,
          turn_id = ctx.turn_id,
        })
        opts.on_messages_add({ msg })
      end
    elseif content_block and content_block.type == "tool_use" then
      if opts.on_messages_add then
        local msg = HistoryMessage:new("assistant", {
          type = "tool_use",
          name = content_block.name,
          id = content_block.id,
          input = content_block.input,
        }, {
          state = "generated",
          uuid = content_block.uuid,
          turn_id = ctx.turn_id,
        })
        opts.on_messages_add({ msg })
      end
    end
    
  elseif json.type == "message_delta" then
    if json.delta and json.delta.stop_reason and opts.on_stop then
      local usage = nil
      if ctx.usage then
        usage = {
          prompt_tokens = (ctx.usage.input_tokens or 0) + (ctx.usage.cache_creation_input_tokens or 0),
          completion_tokens = (ctx.usage.output_tokens or 0) + (ctx.usage.cache_read_input_tokens or 0),
        }
      end
      
      local reason = json.delta.stop_reason == "end_turn" and "complete" or json.delta.stop_reason
      opts.on_stop({ reason = reason, usage = usage })
    end
    
  elseif json.type == "message_stop" then
    if opts.on_stop then
      opts.on_stop({ reason = "complete" })
    end
  end
end

-- Non-streaming response handling
function M:parse_response_without_stream(data, event_state, opts)
  if not data or data == "" then return end

  local ok, json = pcall(vim.json.decode, data)
  if not ok then
    opts.on_stop({ reason = "error", error = "Failed to parse response" })
    return
  end

  if json.content and type(json.content) == "table" then
    for _, content_block in ipairs(json.content) do
      if content_block.type == "text" and content_block.text then
        opts.on_chunk(content_block.text)
      end
    end
  end

  opts.on_stop({ reason = "complete" })
end

return M
