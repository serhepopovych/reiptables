#!/usr/bin/gawk -f

# Source USRXML database parsing library.
@include "@target@/netctl/lib/awk/libusrxml.awk"

function usrxml__user_cb(h, nataddr, username, umap, map, dec,
			 n, i, j, p, t)
{
	t = sprintf("skbmark 0x%08x comment \"%s -> %s\"",
		    umap["fen"]["mark"], username, nataddr);

	# h,userid,natid6?,"netx"
	i = map[h,nataddr,username] SUBSEP "netx";

	n = umap[i,"num"];
	for (p = 0; p < n; p++) {
		# h,userid,natid6?,"netx",id
		j = i SUBSEP p;

		# Skip hole entries
		if (!(j in umap))
			continue;

		printf "%s %s\n", umap[j], t >>umap["fen"]["fipset"];
	}

	# Comma separated list of users for this NAT
	t = umap["fen"]["users"];
	if (t)
		t = t ",";
	umap["fen"]["users"] = t username;

	umap["fen"]["nusers"]++;

	return 0;
}

function usrxml__nat_cb(h, nataddr, map, umap, dec,
			n, t, cb, mark, comment)
{
	mark = ++umap["fen"]["mark"];
	umap["fen"]["users"] = "";
	umap["fen"]["nusers"] = 0;

	printf "\n### %s ###\n\n", nataddr >>umap["fen"]["fipset"];

	cb = "usrxml__user_cb";
	usrxml___dyn_for_each(h, nataddr, cb, umap, map);

	n = umap["fen"]["nusers"];
	comment = sprintf("%u user%s: ", n, n != 1 ? "s" : "");

	# XT_MAX_COMMENT_LEN - 1 = 255
	n = 255 - length(comment);

	t = umap["fen"]["users"];
	if (length(t) > n) {
		n -= 3;
		if (substr(t, n, 1) != ",")
			n--;
		t = substr(t, 1, n);
		sub(",[^,]*$", "", t);
		t = t ",...";
	}

	comment = comment t;

	printf "-A %s " \
	       "-m mark --mark 0x%08x -m comment --comment \"%s\" " \
	       "-j SNAT --to-source %s\n",
	       umap["fen"]["chain"],
	       mark, comment,
	       nataddr >>umap["fen"]["fchain"];

	return 0;
}

function usrxml__for_each_nat(h, map, umap, topdir, chain, ipset, mark,
			      s, cb, ret, fchain, fipset)
{
	# s
	s = (umap["tname"] == "nat") ? "4" : "6";

	# topdir
	if (!topdir)
		topdir = ".";

	# chain
	if (!chain)
		chain = "POST-FWD-SNAT-V"s;
	umap["fen"]["chain"] = chain;

	# ipset
	if (!ipset)
		ipset = "post-fwd-snat-v"s;
	umap["fen"]["ipset"] = ipset;

	# mark
	mark = strtonum(mark);
	if (!mark || and(mark, 0xff))
		mark = 0xaa000000;
	umap["fen"]["mark"] = mark;

	# fchain
	if (s == "4")
		s = "";

	fchain = topdir"/usrxml/ip"s"tables/"chain;
	umap["fen"]["fchain"] = fchain;

	printf "\n#\n# %s ip%stables chain.\n#\n", chain, s >fchain;

	# fipset
	fipset = topdir"/usrxml/ipset/"ipset".rules";
	umap["fen"]["fipset"] = fipset;

	printf "\n#\n# %s ipset.\n#\n", ipset >fipset;

	# output rules
	cb = "usrxml__nat_cb";
	ret = usrxml__map_for_each(h, map, cb, umap);

	delete umap["fen"];

	return ret;
}

################################################################################

BEGIN{
	##
	## Initialize user database parser.
	##
	h = init_usrxml_parser("xtables.awk");
	if (h < 0)
		exit 1;
}

{
	##
	## Parse user database.
	##
	line = $0;
	if (run_usrxml_parser(h, line) < 0)
		exit 1;
}

END{
	##
	## Configuration.
	##

	#
	# Setup pathes if variables are empty.
	#
	if (nctl_prefix == "")
		nctl_prefix ="@target@/netctl";

	if (reiptables_dir == "")
		reiptables_dir = nctl_prefix"/etc/reiptables";
	if (reiptables_datadir == "")
		reiptables_datadir = reiptables_dir"/data";

	if (reip6tables_dir == "")
		reip6tables_dir = nctl_prefix"/etc/reip6tables";
	if (reip6tables_datadir == "")
		reip6tables_datadir = reip6tables_dir"/data";

	# nat
	usrxml__for_each_nat(h, USRXML_nats, USRXML_usernats,
			     reiptables_datadir, chain4, ipset4, mark4);
	# nat6
	usrxml__for_each_nat(h, USRXML_nats6, USRXML_usernats6,
			     reip6tables_datadir, chain6, ipset6, mark6);

	##
	## Finish user database parsing.
	##
	if (fini_usrxml_parser(h) < 0)
		exit 1;
}
