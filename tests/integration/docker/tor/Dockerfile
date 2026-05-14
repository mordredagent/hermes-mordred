# Minimal Tor image for PR3b integration tests.
#
# Uses alpine + the distro `tor` package so we don't depend on a third
# party tagged image. Bumping alpine major.minor is a single-line edit.
FROM alpine:3.20

RUN apk add --no-cache tor && \
    mkdir -p /var/log/tor && \
    touch /var/log/tor/notices.log && \
    chown -R tor:tor /var/log/tor

COPY torrc /etc/tor/torrc

USER tor
EXPOSE 9050

CMD ["tor", "-f", "/etc/tor/torrc"]
