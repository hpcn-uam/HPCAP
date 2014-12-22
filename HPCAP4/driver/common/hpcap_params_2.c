{ /* # of RX queues with RSS (RXQ) */
	static DRIVER_OPTION opt = {
		.type = range_option,
		.name = "RX queues (RXQ)",
		.err  = "using default.",
		.def  = 1,
		.arg  = { .r = { .min = 0,
				#if defined(HPCAP_IXGBE)
				 .max = IXGBE_MAX_RSS_INDICES}}
				#elif defined(HPCAP_IXGBEVF)
				 .max = IXGBEVF_MAX_RSS_INDICES}}
				#endif
		};
	unsigned int rxq = RXQ[bd];

	#ifdef module_param_array
	if ( !(num_RXQ > bd) )
	{
		rxq = opt.def;
	}
	#endif
	switch (rxq) {
		case 0:
			/*
			* Base it off num_online_cpus() with
			* a hardware limit cap.
			*/
			#if defined(HPCAP_IXGBE)
				rxq = min(IXGBE_MAX_RSS_INDICES, (int)num_online_cpus());
			#elif defined(HPCAP_IXGBEVF)
				rxq = min(IXGBEVF_MAX_RSS_INDICES, (int)num_online_cpus());
			#endif
			break;
		default:
			DRIVER_VALIDATE_OPTION(&rxq, &opt);
			break;
	}
	#if !defined(HPCAP_IXGBEVF)
		feature[RING_F_RXQ].indices = rxq;
		*aflags |= IXGBE_FLAG_RSS_ENABLED;
	#endif
}

{ /* # of TX queues (TXQ) */
	static DRIVER_OPTION opt = {
		.type = range_option,
		.name = "TX queues (TXQ)",
		.err  = "using default.",
		.def  = 1,
		.arg  = { .r = { .min = 0,
				#if defined(HPCAP_IXGBE)
				 .max = IXGBE_MAX_RSS_INDICES}}
				#elif defined(HPCAP_IXGBEVF)
				 .max = IXGBEVF_MAX_RSS_INDICES}}
				#endif
			};
	unsigned int txq = TXQ[bd];

	#ifdef module_param_array
	if ( !(num_TXQ > bd) )
	{
		txq = opt.def;
	}
	#endif
	switch (txq) {
		case 0:
			/*
			* Base it off num_online_cpus() with
			* a hardware limit cap.
			*/
			#if defined(HPCAP_IXGBE)
				txq = min(IXGBE_MAX_RSS_INDICES, (int)num_online_cpus());
			#elif defined(HPCAP_IXGBEVF)
				txq = min(IXGBEVF_MAX_RSS_INDICES, (int)num_online_cpus());
			#endif
			break;
		default:
			DRIVER_VALIDATE_OPTION(&txq, &opt);
			break;
	}
	#if !defined(HPCAP_IXGBEVF)
		feature[RING_F_TXQ].indices = txq;
	#endif
}

{ /* CORE assignment */
	static DRIVER_OPTION opt = {
		.type = range_option,
		.name = "Core to copy from",
		.err  = "defaulting to 0",
		.def  = 0,
		.arg  = { .r = { .min = 0,
				 .max = (MAX_NUMNODES - 1)}}
		};
	int core_param = opt.def;

	/* if the default was zero then we need to set the
	* default value to an online node, which is not
	* necessarily zero, and the constant initializer
	* above can't take first_online_node */
	if (core_param == 0)
		/* must set opt.def for validate */
		opt.def = core_param = first_online_node;
	#ifdef module_param_array
	if (num_Core > bd)
	{
	#endif
		core_param = Core[bd];
		DRIVER_VALIDATE_OPTION((uint *)&core_param, &opt);

		if (core_param != OPTION_UNSET)
		{
			DPRINTK(PROBE, INFO, "core set to %d\n", core_param);
		}
	#ifdef module_param_array
	}
	#endif

	adapter->core = core_param;
	printk("PARAM: Adapter %s core = %d\n",adapter->netdev->name, adapter->core);
}

{ /* Mode assignment */
	static DRIVER_OPTION opt = {
		.type = range_option,
		.name = "RX mode",
		.err  = "defaulting to 1",
		.def  = 1,
		.arg  = { .r = { .min = 1,
				 .max = 2}}
		};
	int mode_param = opt.def;

	#ifdef module_param_array
	if (num_Mode> bd)
	{
	#endif
		mode_param = Mode[bd];
		DRIVER_VALIDATE_OPTION((uint *)&mode_param, &opt);
	#ifdef module_param_array
	}
	#endif

	adapter->work_mode = mode_param;
	printk("PARAM: Adapter %s mode = %d\n",adapter->netdev->name, adapter->work_mode);
}

{ /* Dup assignment */
	static DRIVER_OPTION opt = {
	.type = range_option,
	.name = "Dup",
	.err  = "defaulting to 0",
	.def  = 0,
	.arg  = { .r = { .min = 0,
			 .max = 1}}
	};
	int dup_param = opt.def;

	#ifdef module_param_array
	if (num_Dup> bd)
	{
	#endif
		dup_param = Dup[bd];
		DRIVER_VALIDATE_OPTION((uint *)&dup_param, &opt);
	#ifdef module_param_array
	}
	#endif
	adapter->dup_mode = dup_param;
	printk("PARAM: Adapter %s dup = %d\n",adapter->netdev->name, adapter->dup_mode);
}

{ /* Caplen assignment */
	static DRIVER_OPTION opt = {
		.type = range_option,
		.name = "Capture length",
		.err  = "defaulting to 0",
		.def  = 0,
		.arg  = { .r = { .min = 0,
				 .max = MAX_PACKET_SIZE}}
		};
	int caplen_param = opt.def;

	#ifdef module_param_array
	if (num_Caplen> bd)
	{
	#endif
		caplen_param = Caplen[bd];
		DRIVER_VALIDATE_OPTION((uint *)&caplen_param, &opt);
	#ifdef module_param_array
	}
	#endif

	adapter->caplen = caplen_param;
	printk("PARAM: Adapter %s Caplen = %d\n",adapter->netdev->name, adapter->caplen);
}

{ /* Pages assignment */
	static DRIVER_OPTION opt = {
		.type = range_option,
		.name = "Kernel buffer pages",
		.err  = "Invalid value",
		.def  = 1,
		.arg  = { .r = { .min = 1,
				 .max = HPCAP_BUF_SIZE/PAGE_SIZE}}
		};
	int pages_param = opt.def;

	#ifdef module_param_array
	if (num_Pages> bd)
	{
	#endif
		pages_param = Pages[bd];
		DRIVER_VALIDATE_OPTION((uint *)&pages_param, &opt);
	#ifdef module_param_array
	}
	#endif

	adapter->bufpages = pages_param;
	printk("PARAM: Adapter %s Pages = %d\n",adapter->netdev->name, adapter->bufpages);
}
