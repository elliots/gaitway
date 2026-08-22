Gaitway - The AI Gateway
------------------------

Gaitway is an AI gateway for enterprises, initially only targeting Claude.

See: https://code.claude.com/docs/en/gateways

It has the following features:

 - Records all requests and responses, tracking by account/user
 - Emits opentelemetry
   - Analyse usage. Check if 'agentic' or human
   - Track code language, tool usage etc etc
   - 
 - Usage tracking per user
   - Set warning level limits
   - Limits per time period (certain amount per hour etc)
   - Maybe force failover to smaller or open source model on overage?
   - Check for sessions where there is excessive context over time (> 300k etc) for warnings until confirmed (return a tool for 'confirm you are ok with this usage, its spent $8 over the last 5 minutes' ui in claude code?)
 - Can run scans of the outgoing requests:
   - PII, secrets etc
   - Other plugins
 - Can be configured with its own tools
   - Available tools are injected into outgoing messages
   - Tool usage is handled at gateway, interleaving with tool usage from claude code
   - To maintain full history, the tool output must be injected back into the api response so claude code knows about it for next request. This will need thinking about and testing for best approach. see `./design.md`


Technology:

 - Plugin architecture (compile-time is fine for now, but runtime may also be useful later)
 - Golang
 - Postgres db


Note that `./design.md` was generated, if there are any clased between this file and design.md, ask before creating the plan.md