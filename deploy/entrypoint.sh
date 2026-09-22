#!/bin/sh
set -eu
umask 077
# Preserve the approved isolated trial addressing. Edit these explicit public
# ranges in Git when adding different service addresses; no firewall hooks.
: "${TUNNEL_ADDRESS:?Set the approved tunnel /32}"
: "${TUNNEL_ROUTES:?Set the approved peer /32 routes}"
case "$TUNNEL_ADDRESS" in 10.77.0.1/32|10.77.0.254/32) ;; *) exit 2 ;; esac
for route in $TUNNEL_ROUTES; do
    case "$route" in 10.77.0.1/32|10.77.0.2/32|10.77.0.253/32|10.77.0.254/32) ;; *) exit 2 ;; esac
done
test -r /config/wg0.conf
test -r /config/stunmesh.yml
# wg setconf is the official WG parser, not wg-quick; shell hooks/DNS commands
# are not supported. All interface/address/route changes stay in this netns.
/bin/busybox ip link add wg0 type wireguard
/usr/local/bin/wg setconf wg0 /config/wg0.conf
/bin/busybox ip address add "$TUNNEL_ADDRESS" dev wg0
/bin/busybox ip link set dev wg0 mtu 1280 up
for route in $TUNNEL_ROUTES; do
    /bin/busybox ip route add "$route" dev wg0
done
printf '%s\n' 'WireGuard initialized in the owned network namespace'
exec /usr/local/bin/stunmesh-go -c /config/stunmesh.yml
