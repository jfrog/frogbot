# Bare Alpine: only packages needed to reproduce `curl .../getFrogbot.sh | sh`.
FROM alpine:3.20

RUN apk add --no-cache curl python3

WORKDIR /test
COPY mock_server.py getFrogbot.before.sh getFrogbot.after.sh run-in-container.sh ./
RUN chmod +x run-in-container.sh

CMD ["/bin/sh", "/test/run-in-container.sh"]
