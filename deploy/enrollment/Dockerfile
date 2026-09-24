# Three locally verified static executables. No shell, network stack utilities,
# package manager, source checkout, credentials, or background service.
FROM scratch
COPY --chmod=0755 provision /usr/local/bin/provision
COPY --chmod=0755 wg /usr/local/bin/wg
COPY --chmod=0755 qrencode /usr/local/bin/qrencode
USER 0:0
ENTRYPOINT ["/usr/local/bin/provision"]
