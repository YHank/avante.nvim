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

-- Inherit from Claude provider (for utility functions)
-- setmetatable(M, { __index = Claude })

M.api_key_name = nil  -- nil로 설정하여 require_api_key가 false를 반환하도록 함
M.tokenizer_id = "gpt-4o"  -- claude tokenizer가 없으므로 gpt-4o 사용
M.support_prompt_caching = true
M.role_map = {
  user = "user",
  assistant = "assistant",
}

-- Override parse_api_key to return nil (no API key needed for OAuth)
function M.parse_api_key()
  return nil
end

-- Needed functions from Claude provider
function M:transform_tool(tool)
  local input_schema_properties, required = Utils.llm_tool_param_fields_to_json_schema(tool.param.fields)
  return {
    name = tool.name,
    description = tool.get_description and tool.get_description() or tool.description,
    input_schema = {
      type = "object",
      properties = input_schema_properties,
      required = required,
    },
  }
end

function M:is_disable_stream() return false end

function M:parse_messages(opts)
  local messages = {}
  local provider_conf, _ = Providers.parse_config(self)

  -- context 메시지 수집
  local context_content = ""
  for _, message in ipairs(opts.messages) do
    if message.is_context then
      if context_content ~= "" then
        context_content = context_content .. "\n\n"
      end
      context_content = context_content .. message.content
    end
  end

  -- 강제로 .avanterules 지침 추가 (OAuth 제약 우회)
  local forced_instructions = [[
항상 root project/*.avanterules 파일을 참고하세요.
항상 한글로 답변하세요.

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

            -- context가 있으면 추가 (토큰 제한 고려)
            if context_content and context_content ~= "" then
              -- context 길이 제한 (토큰 절약)
              local max_context_length = 10000
              if #context_content > max_context_length then
                context_content = context_content:sub(1, max_context_length) .. "..."
              end
              full_content = full_content .. "\n\n=== 프로젝트 컨텍스트 ===\n" .. context_content
            end

            content_items = full_content .. "\n\n" .. content_items
            first_user_msg_processed = true
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

  return messages, context_content
end

---@class ClaudeLLMOrcState
---@field oauth_token table?
M.state = nil

-- Decrypt LLM-ORC credentials
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
  -- 강제 디버그 출력 (vim.notify 사용) - 주석 처리
  -- local user_count = 0
  -- local assistant_count = 0
  -- local context_count = 0
  -- local avanterules_found = false
  -- local tools_count = 0

  -- for _, msg in ipairs(prompt_opts.messages or {}) do
  --   if msg.is_context then
  --     context_count = context_count + 1
  --     -- .avanterules 관련 내용 확인
  --     if msg.content and (msg.content:match("제1원칙") or msg.content:match("한글로")) then
  --       avanterules_found = true
  --     end
  --   elseif msg.role == "user" then
  --     user_count = user_count + 1
  --   elseif msg.role == "assistant" then
  --     assistant_count = assistant_count + 1
  --   end
  -- end

  -- -- Tools 확인
  -- if prompt_opts.tools then
  --   tools_count = #prompt_opts.tools
  -- end

  -- vim.notify(string.format("LLM-ORC Debug: Messages - user:%d, assistant:%d, context:%d, avanterules:%s, tools:%d",
  --   user_count, assistant_count, context_count, tostring(avanterules_found), tools_count), vim.log.levels.WARN)

  -- 디버그: prompt_opts 구조 확인 - 주석 처리
  -- if vim.g.avante_debug then
  --   Utils.info("LLM-ORC: prompt_opts.messages count = " .. #(prompt_opts.messages or {}))
  --   Utils.info("LLM-ORC: prompt_opts.system_prompt = " .. (prompt_opts.system_prompt or "nil"))
  --   -- Utils.info(string.format("LLM-ORC: Messages - user:%d, assistant:%d, context:%d, avanterules:%s",
  --   --   user_count, assistant_count, context_count, tostring(avanterules_found)))
  -- end

  -- Load OAuth token from LLM-ORC if not already loaded
  if not M.state or not M.state.oauth_token then
    local token_data, err = decrypt_credentials()
    if not token_data then
      -- Utils.error(err)
      error("Failed to load LLM-ORC credentials")
    end

    M.state = M.state or {}
    M.state.oauth_token = token_data
  end

  -- Check if token is expired
  local now = os.time()
  -- if M.state.oauth_token.expires_at and M.state.oauth_token.expires_at <= now then
  --   Utils.warn("LLM-ORC OAuth token is expired. Please refresh with: llm-orc auth add anthropic-claude-pro-max")
  -- end

  local provider_conf, request_body = Providers.parse_config(self)
  local disable_tools = provider_conf.disable_tools or false

  -- Build our own curl args instead of using Claude's
  local messages, context_content = self:parse_messages(prompt_opts)

  -- OAuth requires EXACTLY this system prompt - cannot be modified
  local system_prompt = "You are Claude Code, Anthropic's official CLI for Claude."
  -- Additional prompts from .avanterules cannot be added with OAuth

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

  -- Debug logging
  -- Utils.info("LLM-ORC OAuth provider loaded successfully!")

  -- Always save debug info
  -- local debug_file = "/tmp/avante_llm_orc_debug.json"
  -- local f = io.open(debug_file, "w")
  -- if f then
  --   f:write(vim.json.encode({
  --     headers = curl_args.headers,
  --     url = curl_args.url,
  --     body = curl_args.body,
  --     original_messages = prompt_opts.messages,
  --     parsed_messages = messages
  --   }))
  --   f:close()
  -- end

  -- if vim.g.avante_debug then
  --   Utils.info("LLM-ORC Headers: " .. vim.inspect(curl_args.headers))
  --   Utils.info("LLM-ORC URL: " .. curl_args.url)
  --   Utils.info("LLM-ORC Model: " .. curl_args.body.model)
  --   Utils.info("LLM-ORC Token: Bearer " .. M.state.oauth_token.access_token:sub(1, 20) .. "...")
  --   Utils.info("LLM-ORC Debug saved to: " .. debug_file)
  -- end

  return curl_args
end

function M.is_env_set()
  -- Check if LLM-ORC credentials exist
  return llm_orc_credentials_file:exists() and llm_orc_encryption_key_file:exists()
end

function M.setup()
  -- Utils.info("LLM-ORC: setup() called")

  if not M.is_env_set() then
    -- Utils.warn("LLM-ORC credentials not found. Please run: llm-orc auth add anthropic-claude-pro-max")
    return
  end

  -- Try to load credentials
  local token_data, err = decrypt_credentials()
  if not token_data then
    -- Utils.error(err)
    return
  end

  M.state = { oauth_token = token_data }

  require("avante.tokenizers").setup(M.tokenizer_id)
  vim.g.avante_claude_llm_orc_login = true

  -- Utils.info("LLM-ORC: setup() completed successfully")
end

-- Error handling
function M.on_error(result)
  -- Debug: Log error
  -- Utils.warn("LLM-ORC Error - Status: " .. tostring(result.status))
  -- if result.body then
  --   Utils.warn("LLM-ORC Error Body: " .. result.body:sub(1, 200))
  -- end

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
    -- 여기서 fallback을 트리거할 수 있지만, 일단 에러는 표시
    error_msg = "System prompt modification not supported. " .. error_msg
  end

  Utils.error(error_msg, { once = true, title = "Avante" })
end

-- Stream parsing - using Claude's format (ctx, data_stream, event_state, opts)
function M:parse_response(ctx, data_stream, event_state, opts)
  -- Claude provider 형식과 동일하게 처리
  if not data_stream or data_stream == "" then return end

  -- Initialize content_blocks if needed
  if ctx.content_blocks == nil then ctx.content_blocks = {} end

  local ok, json = pcall(vim.json.decode, data_stream)
  if not ok then return end

  -- Debug
  -- if vim.g.avante_debug then
  --   Utils.info(string.format("LLM-ORC: Parsing %s", json.type or "unknown"))
  -- end

  if json.type == "message_start" then
    if json.message then
      ctx.message_id = json.message.id
      ctx.role = json.message.role or ctx.role
      if json.message.usage and opts.update_tokens_usage then
        opts.update_tokens_usage(json.message.usage)
      end
    end
  elseif json.type == "content_block_start" then
    local content_block = json.content_block or {}
    content_block.stopped = false
    ctx.content_blocks[json.index + 1] = content_block

    if content_block.type == "text" then
      local msg = HistoryMessage:new({
        role = "assistant",
        content = content_block.text or "",
      }, {
        state = "generating",
        turn_id = ctx.turn_id,
      })
      content_block.uuid = msg.uuid
      if opts.on_messages_add then opts.on_messages_add({ msg }) end
    elseif content_block.type == "tool_use" and opts.on_messages_add then
      -- Tool use 처리 (attempt_completion 등)
      -- claude.lua와 동일하게 처리
      local incomplete_json = nil  -- OAuth는 input_json을 제공하지 않을 수 있음
      if content_block.input_json then
        incomplete_json = vim.json.decode(content_block.input_json)
      end
      local msg = HistoryMessage:new({
        role = "assistant",
        content = {
          {
            type = "tool_use",
            name = content_block.name,
            id = content_block.id,
            input = incomplete_json or {},
          },
        },
      }, {
        state = "generating",
        turn_id = ctx.turn_id,
      })
      content_block.uuid = msg.uuid
      opts.on_messages_add({ msg })
    end
  elseif json.type == "content_block_delta" then
    local content_block = ctx.content_blocks[json.index + 1]
    if not content_block then return end

    if json.delta and json.delta.type == "text_delta" and json.delta.text then
      -- Accumulate text
      content_block.text = (content_block.text or "") .. json.delta.text

      -- Send chunk if on_chunk exists (for other uses)
      if opts.on_chunk then
        opts.on_chunk(json.delta.text)
      end

      -- Update message
      local msg = HistoryMessage:new({
        role = "assistant",
        content = content_block.text,
      }, {
        state = "generating",
        uuid = content_block.uuid,
        turn_id = ctx.turn_id,
      })
      if opts.on_messages_add then opts.on_messages_add({ msg }) end
    elseif json.delta and json.delta.type == "input_json_delta" then
      -- Tool use input delta
      if not content_block.input_json then content_block.input_json = "" end
      content_block.input_json = content_block.input_json .. json.delta.partial_json
    end
  elseif json.type == "content_block_stop" then
    local content_block = ctx.content_blocks[json.index + 1]
    if content_block then
      content_block.stopped = true

      if content_block.type == "text" then
        local msg = HistoryMessage:new({
          role = "assistant",
          content = content_block.text or "",
        }, {
          state = "generated",
          uuid = content_block.uuid,
          turn_id = ctx.turn_id,
        })
        if opts.on_messages_add then opts.on_messages_add({ msg }) end
      elseif content_block.type == "tool_use" then
        -- Tool use 완료 처리
        local complete_json = nil
        if content_block.input_json then
          local ok, parsed = pcall(vim.json.decode, content_block.input_json)
          if ok then complete_json = parsed end
        end

        -- claude.lua와 동일하게 모든 tool_use 처리
        local msg = HistoryMessage:new({
          role = "assistant",
          content = {
            {
              type = "tool_use",
              name = content_block.name,
              id = content_block.id,
              input = complete_json or {},
            },
          },
        }, {
          state = "generated",
          uuid = content_block.uuid,
          turn_id = ctx.turn_id,
        })
        if opts.on_messages_add then opts.on_messages_add({ msg }) end
      end
    end
  elseif json.type == "message_delta" then
    -- Handle stop reason differently
    if json.delta and json.delta.stop_reason then
      -- Mark all content blocks as completed
      for _, content_block in ipairs(ctx.content_blocks or {}) do
        if content_block.type == "text" and content_block.uuid then
          local msg = HistoryMessage:new({
            role = "assistant",
            content = content_block.text or "",
          }, {
            state = "generated",
            uuid = content_block.uuid,
            turn_id = ctx.turn_id,
          })
          if opts.on_messages_add then opts.on_messages_add({ msg }) end
        end
      end

      -- if vim.g.avante_debug then
      --   Utils.info("LLM-ORC: Stop reason - " .. json.delta.stop_reason)
      -- end

      -- 중요: 반드시 on_stop을 호출하여 생성 상태를 종료
      if json.delta.stop_reason == "end_turn" then
        if opts.on_stop then
          opts.on_stop({ reason = "complete", usage = json.usage })
        end
      elseif json.delta.stop_reason == "max_tokens" then
        if opts.on_stop then
          opts.on_stop({ reason = "max_tokens", usage = json.usage })
        end
      elseif json.delta.stop_reason == "tool_use" then
        if opts.on_stop then
          opts.on_stop({ reason = "tool_use", usage = json.usage })
        end
      end
    end
    if json.usage and opts.update_tokens_usage then
      opts.update_tokens_usage(json.usage)
    end
  elseif json.type == "message_stop" then
    -- Ensure all messages are marked as completed
    for _, content_block in ipairs(ctx.content_blocks or {}) do
      if content_block.type == "text" and content_block.uuid and not content_block.stopped then
        local msg = HistoryMessage:new({
          role = "assistant",
          content = content_block.text or "",
        }, {
          state = "generated",
          uuid = content_block.uuid,
          turn_id = ctx.turn_id,
        })
        if opts.on_messages_add then opts.on_messages_add({ msg }) end
      end
    end

    -- Fallback: ensure on_stop is called even if message_delta didn't have stop_reason
    if opts.on_stop then
      opts.on_stop({ reason = "complete" })
    end
  elseif json.type == "error" then
    if opts.on_stop then
      opts.on_stop({ reason = "error", error = json.error })
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

  if json.usage then
    opts.on_state_change({ type = "usage", data = json.usage })
  end

  if json.stop_reason then
    opts.on_state_change({ type = "stop_reason", data = json.stop_reason })
  end
end

return M
