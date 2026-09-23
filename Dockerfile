# Inputs are built/verified locally by scripts/prepare-image.py. No RUN, fetch,
# repository-wide COPY, keys, configuration or compiler in this image.
# busybox + musl originate from the already approved Alpine manifest pinned in
# build/inputs.json; only these two required files are retained.
FROM scratch
COPY --chmod=0755 build/image/busybox /bin/busybox
COPY --chmod=0755 build/image/ld-musl-x86_64.so.1 /lib/ld-musl-x86_64.so.1
COPY --chmod=0755 build/image/wg /usr/local/bin/wg
COPY --chmod=0755 build/image/stunmesh-go /usr/local/bin/stunmesh-go
COPY --chmod=0755 deploy/entrypoint.sh /entrypoint.sh
ENV PATH=/usr/local/bin:/bin
# Namespace root is required to configure the kernel WG interface. Rootless
# Podman maps it to its calling service user, never to host root.
USER 0:0
ENTRYPOINT ["/bin/busybox", "sh", "/entrypoint.sh"]
