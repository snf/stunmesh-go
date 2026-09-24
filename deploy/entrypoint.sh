#!/bin/sh
set -efu
umask 077
# Preserve the isolated trial subnet. Only explicit host routes are accepted;
# enrollment can allocate new phone addresses without changing this script.
: "${TUNNEL_ADDRESS:?Set the approved tunnel /32}"
: "${TUNNEL_ROUTES:?Set the approved peer /32 routes}"
case "$TUNNEL_ADDRESS" in 10.77.0.1/32|10.77.0.254/32) ;; *) exit 2 ;; esac
for route in $TUNNEL_ROUTES; do
    case "$route" in
        10.77.0.[1-9]/32|10.77.0.[1-9][0-9]/32|10.77.0.1[0-9][0-9]/32|10.77.0.2[0-4][0-9]/32|10.77.0.25[0-4]/32) ;;
        *) exit 2 ;;
    esac
done
test -r /config/wg0.conf
test -r /config/stunmesh.yml
# wg setconf is the official WG parser, not wg-quick; shell hooks/DNS commands
# are not supported. All interface/address/route changes stay in this netns.
/bin/busybox ip link add wg0 type wireguard
/usr/local/bin/wg setconf wg0 /config/wg0.conf
/bin/busybox ip address add "$TUNNEL_ADDRESS" dev wg0
if test "$TUNNEL_ADDRESS" = 10.77.0.1/32; then
    # Fixed NAS service aliases, not routes to the physical LAN. The separate
    # reviewed TCP listeners connect onward from this disposable namespace.
    /bin/busybox ip address add 10.77.0.21/32 dev wg0
    /bin/busybox ip address add 10.77.0.23/32 dev wg0
fi
/bin/busybox ip link set dev wg0 mtu 1280 up
for route in $TUNNEL_ROUTES; do
    /bin/busybox ip route add "$route" dev wg0
done
printf '%s\n' 'WireGuard initialized in the owned network namespace'
exec /usr/local/bin/stunmesh-go -c /config/stunmesh.yml
