# maubot-linear

A [maubot](https://github.com/maubot/maubot) plugin that lets Matrix users interact with [Linear](https://linear.app) by mentioning the bot. Uses the Claude API with tool-use and Linear's hosted MCP server — no custom GraphQL needed.

## How it works

```
User mentions bot in Matrix room
  → Plugin resolves user's Linear token
  → Fetches tool definitions from Linear MCP server
  → Claude decides which Linear tools to call
  → Plugin forwards tool calls to Linear MCP
  → Claude summarizes the result
  → Bot replies in Matrix
```

## Usage

Mention the bot followed by a natural language instruction:

| Action | Example |
|--------|---------|
| Create ticket | `@Linear create a triage ticket in team Engineering about login timeouts` |
| Edit ticket | *(reply to ticket msg)* `@Linear change the title to "Auth timeout on mobile"` |
| Close ticket | *(reply to ticket msg)* `@Linear close this` |
| Reassign | *(reply to ticket msg)* `@Linear reassign to Jane` |
| Add comment | *(reply to ticket msg)* `@Linear add a comment: investigated, this is a backend issue` |

When replying to a message the bot sent about a ticket, the issue context is automatically resolved.

### Commands

| Command | Description |
|---------|-------------|
| `!linear link` | Link your Linear account (OAuth or token instructions) |
| `!linear unlink` | Remove your linked account |
| `!linear token <key>` | Set your API key (**DM only** — the bot will redact if sent in a room) |
| `!linear status` | Check if your account is linked |

## Setup

### Requirements

- maubot 0.3.0+
- An Anthropic API key

### Install

```sh
make build
```

Upload `linear_bot.mbp` to your maubot instance.

### Configuration

```yaml
# Required
anthropic_api_key: "sk-ant-..."

# Optional
claude_model: "claude-sonnet-4-6"    # Claude model to use
allowed_users: []                      # Empty = everyone allowed
max_tool_rounds: 5                     # Max tool-use iterations per request

# OAuth (optional — if unset, users link via !linear token in DMs)
linear_client_id: ""
linear_client_secret: ""
linear_redirect_uri: ""                # e.g. https://maubot.example.com/_matrix/maubot/plugin/<instance>/linear/callback
```

### Linking accounts

**Without OAuth:** Users DM the bot with `!linear token <api-key>`. API keys can be created at https://linear.app/settings/api.

**With OAuth:** Set `linear_client_id`, `linear_client_secret`, and `linear_redirect_uri` in the config. Users run `!linear link` to start the OAuth flow. The redirect URI must point to your maubot instance at the path shown above.

## Security notes

- Tokens are stored **in plaintext** in the maubot SQLite database. Protect your maubot instance accordingly.
- The `!linear token` command only accepts tokens via DM. If sent in a room, the bot warns the user and attempts to redact the message.
- Each user authenticates with their own Linear token — the bot acts on behalf of the mentioning user.

## Architecture

| File | Purpose |
|------|---------|
| `linear_bot.py` | Main plugin: mention handler, commands, OAuth, reply context |
| `mcp_client.py` | MCP JSON-RPC client (session management, tool caching) |
| `claude_client.py` | Claude API tool-use loop bridging to MCP |
| `store.py` | Database: user tokens + ticket link mappings |
