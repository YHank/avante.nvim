local Path = require("plenary.path")
local Utils = require("avante.utils")
local Providers = require("avante.providers")
local Claude = require("avante.providers.claude")
local HistoryMessage = require("avante.history.message")

local H = {}

---@class AvanteProviderFunctor
local M = {}

-- Helper functions for message parsing
local MessageParser = {}

-- Helper functions for streaming
local StreamHandler = {}

---@class ClaudeLLMOrcConfig
---@field max_context_length integer
---@field token_refresh_interval integer
---@field token_refresh_threshold integer
---@field enable_auto_refresh boolean
---@field retry_delay integer
---@field max_retries integer
local default_config = {
  max_context_length = 15000,
  token_refresh_interval = 300, -- 5 minutes in seconds
  token_refresh_threshold = 300, -- refresh if token expires in less than 5 minutes
  enable_auto_refresh = true,
  retry_delay = 1000, -- milliseconds
  max_retries = 3,
}

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

-- Config management
M.config = vim.tbl_deep_extend("force", default_config, {})

---@param opts? ClaudeLLMOrcConfig
function M.update_config(opts)
  if opts then
    M.config = vim.tbl_deep_extend("force", M.config, opts)
  end
end

-- Override parse_api_key to return nil (no API key needed for OAuth)
function M.parse_api_key()
  return nil
end

-- Use Claude's tool transformation
function M:transform_tool(tool)
  return Claude:transform_tool(tool)
end

function M:is_disable_stream() return false end

-- Build system instructions from forced rules and context
function MessageParser.build_system_instructions(context_content, selected_code_content, has_selected_code)
  local instructions = [[
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
  
  -- Add selected code if available
  if has_selected_code and selected_code_content ~= "" then
    instructions = instructions .. "\n\n=== 선택된 코드 (이 코드를 기반으로 작업하세요) ===\n" .. selected_code_content
    instructions = instructions .. "\n\n위의 선택된 코드를 수정하거나 개선한 결과를 <code></code> 태그로 제공하세요."
  end
  
  -- Add general context if available (with token limit)
  if context_content and context_content ~= "" then
    instructions = instructions .. "\n\n=== 프로젝트 컨텍스트 ===\n" .. MessageParser.optimize_context(context_content)
  end
  
  return instructions
end

-- Optimize context to fit within token limits
function MessageParser.optimize_context(context_content)
  local max_context_length = M.config.max_context_length or 15000
  if #context_content > max_context_length then
    return MessageParser.smart_truncate(context_content, max_context_length)
  end
  return context_content
end

-- Smart truncation that preserves important information
function MessageParser.smart_truncate(content, max_length)
  -- Try to preserve complete sections
  local truncated = content:sub(1, max_length)
  
  -- Find last complete paragraph or section
  local last_newline = truncated:find("\n[^\n]*$")
  if last_newline then
    truncated = truncated:sub(1, last_newline - 1)
  end
  
  return truncated .. "\n...\n(context truncated)"
end

-- Extract context messages from the message list
function MessageParser.extract_context_messages(messages)
  local context_content = ""
  local selected_code_content = ""
  local has_selected_code = false
  
  for _, message in ipairs(messages) do
    if message.is_context then
      local content = message.content
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
  
  return context_content, selected_code_content, has_selected_code
end

-- Validate messages before processing
function MessageParser.validate_messages(messages)
  if not messages or #messages == 0 then
    return false, "No messages to process"
  end
  
  -- Check for required message structure
  for _, msg in ipairs(messages) do
    if not msg.role then
      return false, "Message missing role"
    end
    if not msg.content and not msg.is_context then
      return false, "Message missing content"
    end
  end
  
  return true
end

function M:parse_messages(opts)
  local messages = {}
  local provider_conf, _ = Providers.parse_config(self)
  
  -- Validate messages
  local valid, err = MessageParser.validate_messages(opts.messages)
  if not valid then
    error("Invalid messages: " .. err)
  end
  
  -- Extract context messages
  local context_content, selected_code_content, has_selected_code = 
    MessageParser.extract_context_messages(opts.messages)

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
          -- Process first user message with system instructions
          if message.role == "user" and not first_user_msg_processed then
            local system_instructions = MessageParser.build_system_instructions(
              context_content, selected_code_content, has_selected_code
            )
            content_items = system_instructions .. "\n\n=== 사용자 요청 ===\n" .. content_items
            first_user_msg_processed = true
          elseif message.role == "user" and has_selected_code then
            -- Add reference to selected code for subsequent messages
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
---@field refresh_timer uv_timer_t?
---@field is_refreshing boolean
M.state = nil

-- Timer management functions
local function stop_refresh_timer()
  if M.state and M.state.refresh_timer then
    M.state.refresh_timer:stop()
    M.state.refresh_timer:close()
    M.state.refresh_timer = nil
  end
end

local function setup_refresh_timer()
  if not M.config.enable_auto_refresh then return end
  if not M.state or not M.state.oauth_token then return end
  
  stop_refresh_timer()
  
  M.state.refresh_timer = vim.uv.new_timer()
  if not M.state.refresh_timer then return end
  
  local interval = M.config.token_refresh_interval * 1000
  M.state.refresh_timer:start(
    interval,
    interval,
    vim.schedule_wrap(function()
      H.refresh_oauth_token(true)
    end)
  )
end

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

-- OAuth token refresh with better error handling
function H.refresh_oauth_token(async, force)
  if not M.state then
    error("internal initialization error")
  end
  
  async = async == nil and true or async
  force = force or false
  
  -- Prevent concurrent refresh attempts
  if M.state.is_refreshing then
    if vim.g.avante_debug then
      Utils.info("LLM-ORC: Token refresh already in progress")
    end
    return false
  end
  
  -- Check if token needs refresh
  local now = os.time()
  if not force and M.state.oauth_token and M.state.oauth_token.expires_at then
    local time_until_expiry = M.state.oauth_token.expires_at - now
    if time_until_expiry > M.config.token_refresh_threshold then
      return false
    end
  end
  
  M.state.is_refreshing = true
  
  local function handle_refresh()
    local token_data, err = decrypt_credentials()
    if not token_data then
      M.state.is_refreshing = false
      Utils.error("Failed to refresh OAuth token: " .. (err or "unknown error"))
      return false
    end
    
    -- Verify new token is not expired
    if token_data.expires_at and token_data.expires_at <= now then
      M.state.is_refreshing = false
      Utils.error("LLM-ORC OAuth token is expired. Please refresh with: llm-orc auth add anthropic-claude-pro-max")
      return false
    end
    
    M.state.oauth_token = token_data
    M.state.is_refreshing = false
    
    if vim.g.avante_debug then
      Utils.info("LLM-ORC: OAuth token refreshed successfully")
    end
    
    -- Reset timer if synchronous refresh
    if not async then
      setup_refresh_timer()
    end
    
    return true
  end
  
  if async then
    vim.schedule(handle_refresh)
  else
    return handle_refresh()
  end
end

-- Rate limit handling similar to claude.lua
function M:get_rate_limit_sleep_time(headers)
  local rate_limit_remaining = tonumber(headers["x-ratelimit-remaining"])
  if rate_limit_remaining == nil then return end
  if rate_limit_remaining > 10 then return end
  
  local rate_limit_reset = headers["x-ratelimit-reset"]
  if not rate_limit_reset then return end
  
  local reset_time = tonumber(rate_limit_reset)
  if not reset_time then return end
  
  local now = os.time()
  local sleep_time = reset_time - now
  
  if sleep_time > 0 then
    return sleep_time
  end
end

function M:parse_curl_args(prompt_opts)
  -- Load OAuth token from LLM-ORC if not already loaded
  if not M.state or not M.state.oauth_token then
    local token_data, err = decrypt_credentials()
    if not token_data then
      error("Failed to load LLM-ORC credentials: " .. (err or "unknown error"))
    end

    M.state = M.state or {}
    M.state.oauth_token = token_data
    M.state.is_refreshing = false
  end

  -- Refresh token synchronously if needed (similar to copilot.lua)
  H.refresh_oauth_token(false, false)

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

-- Get current configuration
function M.get_config()
  return vim.deepcopy(M.config)
end

-- Check token status
function M.get_token_status()
  if not M.state or not M.state.oauth_token then
    return { valid = false, reason = "No token loaded" }
  end
  
  local now = os.time()
  local expires_at = M.state.oauth_token.expires_at
  
  if not expires_at then
    return { valid = true, reason = "No expiry information" }
  end
  
  if expires_at <= now then
    return { valid = false, reason = "Token expired", expired_at = expires_at }
  end
  
  local time_remaining = expires_at - now
  return {
    valid = true,
    expires_in = time_remaining,
    expires_at = expires_at,
    will_refresh = time_remaining <= M.config.token_refresh_threshold,
  }
end

function M.setup(opts)
  -- Update config if options provided
  M.update_config(opts)
  
  if not M.is_env_set() then
    return
  end

  -- Try to load credentials
  local token_data, err = decrypt_credentials()
  if not token_data then
    if vim.g.avante_debug then
      Utils.warn("LLM-ORC: " .. (err or "Failed to load credentials"))
    end
    return
  end

  M.state = {
    oauth_token = token_data,
    refresh_timer = nil,
    is_refreshing = false,
  }
  
  -- Setup auto-refresh timer if enabled
  if M.config.enable_auto_refresh then
    setup_refresh_timer()
  end
  
  -- Cleanup on exit
  vim.api.nvim_create_autocmd("VimLeavePre", {
    callback = function()
      stop_refresh_timer()
    end,
  })

  require("avante.tokenizers").setup(M.tokenizer_id)
  vim.g.avante_claude_llm_orc_login = true
  
  if vim.g.avante_debug then
    Utils.info("LLM-ORC: Setup completed successfully")
  end
end

-- Enhanced error handling with retry logic
function M.on_error(result)
  -- Handle rate limits with retry information
  if result.status == 429 then
    local sleep_time = M:get_rate_limit_sleep_time(result.headers)
    if sleep_time then
      Utils.warn(string.format("Rate limited. Please wait %d seconds before retrying.", sleep_time), {
        once = true,
        title = "Avante",
      })
    else
      Utils.warn("Rate limited. Please wait before retrying.", { once = true, title = "Avante" })
    end
    return
  end
  
  if not result.body then
    local error_msg = string.format("API request failed with status %d", result.status)
    
    -- Handle specific HTTP status codes
    if result.status == 401 then
      error_msg = error_msg .. ". OAuth authentication failed. Token may be expired."
      -- Try to refresh token on auth failure
      vim.schedule(function()
        H.refresh_oauth_token(true, true)
      end)
    elseif result.status == 403 then
      error_msg = error_msg .. ". Access forbidden. Check your LLM-ORC permissions."
    elseif result.status >= 500 then
      error_msg = error_msg .. ". Server error. Please try again later."
    elseif result.status == 0 then
      error_msg = "Network error. Please check your internet connection."
    end
    
    return Utils.error(error_msg, { once = true, title = "Avante" })
  end

  local ok, body = pcall(vim.json.decode, result.body)
  if not (ok and body and body.error) then
    return Utils.error("Failed to parse error response: " .. result.body:sub(1, 200), { once = true, title = "Avante" })
  end

  local error_msg = body.error.message
  local error_type = body.error.type

  -- OAuth-specific error handling
  if error_type == "authentication_error" then
    if error_msg:match("x%-api%-key") then
      error_msg = "OAuth authentication failed. Please check your LLM-ORC credentials."
    elseif error_msg:match("token") or error_msg:match("expired") then
      error_msg = "OAuth token expired or invalid. Attempting to refresh..."
      -- Schedule token refresh
      vim.schedule(function()
        if H.refresh_oauth_token(true, true) then
          Utils.info("Token refreshed. Please retry your request.")
        end
      end)
    end
  end

  -- OAuth system prompt restriction handling
  if error_type == "invalid_request_error" and (error_msg:match("system") or error_msg:match("Claude Code")) then
    Utils.warn("System prompt modification not allowed with OAuth. Using required system prompt.")
    -- Don't show the full error to reduce noise
    return
  end
  
  -- Handle token limit errors
  if error_type == "invalid_request_error" and error_msg:match("token") and error_msg:match("limit") then
    error_msg = "Token limit exceeded. Try reducing the context size or message length."
  end

  Utils.error(error_msg, { once = true, title = "Avante" })
end

-- Streaming event handlers
function StreamHandler.handle_message_start(ctx, json, opts)
  if json.message then
    ctx.usage = json.message.usage
  end
end

function StreamHandler.handle_content_block_start(ctx, json, opts)
  local content_block = json.content_block or {}
  ctx.content_blocks[json.index + 1] = content_block
  
  if content_block.type == "thinking" then
    StreamHandler.add_thinking_message(content_block, ctx, opts)
  elseif content_block.type == "text" then
    StreamHandler.add_text_message(content_block, ctx, opts)
  elseif content_block.type == "tool_use" then
    StreamHandler.add_tool_use_message(content_block, ctx, opts)
  end
end

function StreamHandler.add_thinking_message(content_block, ctx, opts)
  if opts.on_chunk then 
    opts.on_chunk("<think>\n") 
  end
  
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
end

function StreamHandler.add_text_message(content_block, ctx, opts)
  content_block.text = content_block.text or ""
  
  if opts.on_messages_add then
    local msg = HistoryMessage:new("assistant", content_block.text, {
      state = "generating",
      turn_id = ctx.turn_id,
    })
    content_block.uuid = msg.uuid
    opts.on_messages_add({ msg })
  end
end

function StreamHandler.add_tool_use_message(content_block, ctx, opts)
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

-- OAuth-specific streaming parser
function M:parse_response(ctx, data_stream, event_state, opts)
  if not data_stream or data_stream == "" then return end
  
  local ok, json = pcall(vim.json.decode, data_stream)
  if not ok then return end
  
  if ctx.content_blocks == nil then ctx.content_blocks = {} end
  
  -- Dispatch to appropriate handler based on event type
  if json.type == "message_start" then
    StreamHandler.handle_message_start(ctx, json, opts)
    
  elseif json.type == "content_block_start" then
    StreamHandler.handle_content_block_start(ctx, json, opts)
    
  elseif json.type == "content_block_delta" then
    StreamHandler.handle_content_block_delta(ctx, json, opts)
    
  elseif json.type == "content_block_stop" then
    StreamHandler.handle_content_block_stop(ctx, json, opts)
    
  elseif json.type == "message_delta" then
    StreamHandler.handle_message_delta(ctx, json, opts)
    
  elseif json.type == "message_stop" then
    StreamHandler.handle_message_stop(ctx, json, opts)
  end
end

-- Content block delta handlers
function StreamHandler.handle_content_block_delta(ctx, json, opts)
  local content_block = ctx.content_blocks[json.index + 1]
  if not content_block then return end
  
  if json.delta and json.delta.type == "thinking_delta" then
    StreamHandler.handle_thinking_delta(content_block, json.delta, ctx, opts)
  elseif json.delta and json.delta.type == "text_delta" and json.delta.text then
    StreamHandler.handle_text_delta(content_block, json.delta, ctx, opts)
  elseif json.delta and json.delta.type == "input_json_delta" and content_block.type == "tool_use" then
    StreamHandler.handle_input_json_delta(content_block, json.delta, ctx, opts)
  end
end

function StreamHandler.handle_thinking_delta(content_block, delta, ctx, opts)
  content_block.thinking = (content_block.thinking or "") .. delta.thinking
  
  if opts.on_chunk then 
    opts.on_chunk(delta.thinking) 
  end
  
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
end

function StreamHandler.handle_text_delta(content_block, delta, ctx, opts)
  content_block.text = (content_block.text or "") .. delta.text
  
  if opts.on_chunk then 
    opts.on_chunk(delta.text) 
  end
  
  if opts.on_messages_add then
    local msg = HistoryMessage:new("assistant", content_block.text, {
      state = "generating",
      uuid = content_block.uuid,
      turn_id = ctx.turn_id,
    })
    opts.on_messages_add({ msg })
  end
end

function StreamHandler.handle_input_json_delta(content_block, delta, ctx, opts)
  local partial_json = delta.partial_json or ""
  content_block.input_json = (content_block.input_json or "") .. partial_json
  
  -- Try to parse JSON
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

-- Content block stop handlers
function StreamHandler.handle_content_block_stop(ctx, json, opts)
  local content_block = ctx.content_blocks[json.index + 1]
  if not content_block then return end
  
  if content_block.type == "thinking" then
    StreamHandler.finish_thinking_message(content_block, ctx, opts)
  elseif content_block.type == "text" then
    StreamHandler.finish_text_message(content_block, ctx, opts)
  elseif content_block.type == "tool_use" then
    StreamHandler.finish_tool_use_message(content_block, ctx, opts)
  end
end

function StreamHandler.finish_thinking_message(content_block, ctx, opts)
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
end

function StreamHandler.finish_text_message(content_block, ctx, opts)
  if opts.on_messages_add then
    local msg = HistoryMessage:new("assistant", content_block.text or "", {
      state = "generated",
      uuid = content_block.uuid,
      turn_id = ctx.turn_id,
    })
    opts.on_messages_add({ msg })
  end
end

function StreamHandler.finish_tool_use_message(content_block, ctx, opts)
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

-- Message delta and stop handlers
function StreamHandler.handle_message_delta(ctx, json, opts)
  if json.delta and json.delta.stop_reason and opts.on_stop then
    local usage = StreamHandler.calculate_usage(ctx.usage)
    local reason = json.delta.stop_reason == "end_turn" and "complete" or json.delta.stop_reason
    opts.on_stop({ reason = reason, usage = usage })
  end
end

function StreamHandler.handle_message_stop(ctx, json, opts)
  if opts.on_stop then
    opts.on_stop({ reason = "complete" })
  end
end

function StreamHandler.calculate_usage(usage)
  if not usage then return nil end
  
  return {
    prompt_tokens = (usage.input_tokens or 0) + (usage.cache_creation_input_tokens or 0),
    completion_tokens = (usage.output_tokens or 0) + (usage.cache_read_input_tokens or 0),
  }
end

-- Non-streaming response handling
function M:parse_response_without_stream(data, event_state, opts)
  if not data or data == "" then return end

  local ok, json = pcall(vim.json.decode, data)
  if not ok then
    if opts.on_stop then
      opts.on_stop({ reason = "error", error = "Failed to parse response" })
    end
    return
  end

  if json.content and type(json.content) == "table" then
    for _, content_block in ipairs(json.content) do
      if content_block.type == "text" and content_block.text then
        if opts.on_chunk then
          opts.on_chunk(content_block.text)
        end
      elseif content_block.type == "thinking" and content_block.thinking then
        if opts.on_chunk then
          opts.on_chunk("<think>\n" .. content_block.thinking .. "\n</think>\n\n")
        end
      elseif content_block.type == "tool_use" then
        -- Handle tool use in non-streaming mode
        if opts.on_messages_add then
          local msg = HistoryMessage:new("assistant", {
            type = "tool_use",
            name = content_block.name,
            id = content_block.id,
            input = content_block.input,
          }, {
            state = "generated",
          })
          opts.on_messages_add({ msg })
        end
      end
    end
  end

  -- Calculate and report usage
  local usage = nil
  if json.usage then
    usage = StreamHandler.calculate_usage(json.usage)
  end

  if opts.on_stop then
    opts.on_stop({ reason = "complete", usage = usage })
  end
end

-- Manual token refresh command
function M.refresh_token()
  if not M.state then
    Utils.error("LLM-ORC provider not initialized")
    return false
  end
  
  local success = H.refresh_oauth_token(false, true)
  if success then
    Utils.info("LLM-ORC token refreshed successfully")
  end
  return success
end

-- Debug information
function M.debug_info()
  local info = {
    config = M.get_config(),
    token_status = M.get_token_status(),
    state = {
      initialized = M.state ~= nil,
      has_token = M.state and M.state.oauth_token ~= nil,
      is_refreshing = M.state and M.state.is_refreshing or false,
      timer_active = M.state and M.state.refresh_timer ~= nil,
    },
    paths = {
      config_dir = tostring(llm_orc_config_dir),
      credentials_file = tostring(llm_orc_credentials_file),
      encryption_key_file = tostring(llm_orc_encryption_key_file),
    },
  }
  return info
end

return M
