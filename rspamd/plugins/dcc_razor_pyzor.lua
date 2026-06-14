--[[
dcc_razor_pyzor.lua — rspamd plugin that checks a message against the three
classic collaborative-filtering networks (DCC, Razor, Pyzor) through a single
local HTTP shim (spamcheck_shim.py).

Why a shim instead of three native modules:
  * rspamd ships a native `dcc` module (talks to dccifd directly), but has no
    native Razor or Pyzor support — those are CLI-only tools.
  * Running the CLIs inside the rspamd worker would block the event loop.
  * The shim runs the CLIs out-of-process and answers over HTTP, so this plugin
    stays fully async (rspamd_http) and one round-trip covers all three.

The shim returns JSON:
  { "dcc":   { "action": "reject"|"accept"|"unknown", "bulk": <int|null> },
    "razor": { "hit": true|false },
    "pyzor": { "count": <int>, "wl": <int> } }

Each backend maps to its own symbol so scores/actions can be tuned per network
in local.d/dcc_razor_pyzor.conf. Configuration (servers, timeouts, scores) is
read from the rspamd config section "dcc_razor_pyzor".
--]]

local rspamd_logger = require "rspamd_logger"
local rspamd_http = require "rspamd_http"
local lua_util = require "lua_util"
local N = "dcc_razor_pyzor"

-- Defaults; overridden by the matching section in local.d/.
local settings = {
  url = "http://127.0.0.1:8077/check",
  timeout = 8.0,
  max_size = 1024 * 1024, -- don't ship messages larger than 1 MiB to the shim
  symbol_dcc = "DRP_DCC_BULK",
  symbol_razor = "DRP_RAZOR",
  symbol_pyzor = "DRP_PYZOR",
  -- DCC "bulk" counter threshold above which we treat it as a hit. "many" maps
  -- to a very large int by the shim, so this also catches the textual verdict.
  dcc_bulk_threshold = 1000,
  -- Pyzor: report count at/above this many sightings is a hit (unless the
  -- whitelist count is non-zero).
  pyzor_count_threshold = 5,
}

local function parse_response(task, body)
  local ucl = require "ucl"
  local parser = ucl.parser()
  local ok, err = parser:parse_string(body)
  if not ok then
    rspamd_logger.errx(task, "cannot parse shim response: %s", err)
    return
  end
  local res = parser:get_object()
  if type(res) ~= "table" then
    rspamd_logger.errx(task, "shim response is not an object")
    return
  end

  -- DCC
  if res.dcc then
    local d = res.dcc
    local bulk = tonumber(d.bulk)
    if d.action == "reject" or (bulk and bulk >= settings.dcc_bulk_threshold) then
      task:insert_result(settings.symbol_dcc, 1.0,
        string.format("bulk=%s", tostring(d.bulk or d.action)))
    end
  end

  -- Razor
  if res.razor and res.razor.hit then
    task:insert_result(settings.symbol_razor, 1.0)
  end

  -- Pyzor
  if res.pyzor then
    local count = tonumber(res.pyzor.count) or 0
    local wl = tonumber(res.pyzor.wl) or 0
    if wl == 0 and count >= settings.pyzor_count_threshold then
      task:insert_result(settings.symbol_pyzor, 1.0,
        string.format("count=%d", count))
    end
  end
end

local function check_cb(task)
  -- Skip empty / oversized messages.
  local content = task:get_content()
  if not content then return end
  if #content > settings.max_size then
    rspamd_logger.infox(task, "skip: message %s bytes exceeds max_size %s",
      #content, settings.max_size)
    return
  end

  local function http_cb(err, code, body)
    if err then
      rspamd_logger.errx(task, "shim request failed: %s", err)
      return
    end
    if code ~= 200 then
      rspamd_logger.errx(task, "shim returned HTTP %s", code)
      return
    end
    parse_response(task, body)
  end

  rspamd_http.request({
    task = task,
    url = settings.url,
    body = content,
    callback = http_cb,
    timeout = settings.timeout,
    method = "POST",
    headers = { ["Content-Type"] = "message/rfc822" },
  })
end

-- Merge user config over defaults.
local opts = rspamd_config:get_all_opt(N)
if opts then
  settings = lua_util.override_defaults(settings, opts)
end

-- Register the async parent symbol that does the round-trip, plus the three
-- virtual result symbols so each network is independently scorable.
local id = rspamd_config:register_symbol({
  name = "DRP_CHECK",
  type = "callback",
  callback = check_cb,
  flags = "empty",
})

for _, s in ipairs({ settings.symbol_dcc, settings.symbol_razor, settings.symbol_pyzor }) do
  rspamd_config:register_symbol({
    name = s,
    type = "virtual",
    parent = id,
  })
end

rspamd_logger.infox(rspamd_config, "%s: registered, shim=%s", N, settings.url)
