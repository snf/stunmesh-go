# Whole-LAN extension: exact proposal, not activated

The initial tested design uses `.0.1`, `.0.21`, `.0.23` service addresses and
fixed TCP forwards. `whole-lan.nft.example` is the separate next-stage proposal
for `10.77.1.1–254 → 192.168.0.1–254`; both `.21` and `.23` remain reserved.
No host/router firewall or forwarding change is needed by the initial design.

This extension genuinely needs forwarding/NAT **inside the disposable rootless
VPN namespace**: destination translation supplies the mapped address view,
source translation gives ordinary LAN hosts a valid return path, and a forward
filter confines that new forwarding to the home LAN. Without these rules,
adding a client `/24` route alone does not deliver whole-LAN access. Ordinary
phone/laptop internet traffic still uses its normal connection.

Review the exact rules before running them. They create one `ip home_map`
table, use the existing `wg0` and verified pasta uplink, and do not alter INPUT
listeners, existing host rules or LAN routing. They admit all authenticated WG
peers to the mapped LAN; application authentication still matters. The `.31`
exception uses pasta's `169.254.1.2` host path and must pass real TCP/UDP tests.
No broadcast discovery, DHCP, IPv6 mapping or default VPN route is provided.

After approval, in a disposable namespace first:

1. Build/review a minimal pinned nftables tools image; record its additional
   libraries. Use only rootless NET_ADMIN. Confirm kernel NAT/conntrack support
   without granting SYS_MODULE or loading modules on the host.
2. Set namespaced `net.ipv4.ip_forward=1`; run `nft --check --file` on this file,
   then load it in that same namespace. Verify TCP, required UDP/ICMP, return
   traffic, the NAS exception and unchanged normal internet routing. Confirm
   unrelated forwarded destinations are dropped and service aliases still work.
3. Record actual syntax/kernel/pasta results before choosing this over fixed
   forwards. The current five-file VPN image does not contain nftables.
4. Only then add `10.77.1.0/24` to newly reviewed client profiles and deploy.
   Rollback inside that namespace: remove exactly table `ip home_map`,
   restore its previous forwarding sysctl, and remove the new client route.
   Recreating the existing VPN namespace also discards these experimental rules.

These are unexecuted acceptance steps, not evidence of working whole-LAN NAT.
The native prefix mapping syntax comes from the
[nftables manual](https://netfilter.org/projects/nftables/manpage.html).
