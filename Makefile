FILES = linear_bot/__init__.py linear_bot/bot.py linear_bot/mcp_client.py \
        linear_bot/claude_client.py linear_bot/store.py maubot.yaml base-config.yaml

build:
	rm -f linear_bot.mbp
	zip linear_bot.mbp $(FILES)
