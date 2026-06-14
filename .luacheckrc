-- luacheck config for the rspamd lua plugin. rspamd injects these globals.
std = "lua53"
max_line_length = 100
read_globals = {
  "rspamd_config",
}
globals = {}
-- rspamd plugins `require` runtime modules that luacheck can't resolve.
ignore = {
  "212",  -- unused argument (callbacks)
}
