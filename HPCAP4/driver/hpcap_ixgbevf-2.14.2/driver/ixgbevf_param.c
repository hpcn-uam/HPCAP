/*******************************************************************************

  Intel 82599 Virtual Function driver
  Copyright (c) 1999 - 2014 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

#include <linux/types.h>
#include <linux/module.h>

#include "ixgbevf.h"
#ifdef DEV_HPCAP
	#include "../../../include/hpcap.h"
#endif /* DEV_HPCAP */

/* This is the only thing that needs to be changed to adjust the
 * maximum number of ports that the driver can manage.
 */

#define IXGBE_MAX_NIC IXGBEVF_MAX_NIC
#define IXGBEVF_MAX_RSS_INDICES 1

#define OPTION_UNSET    -1
#define OPTION_DISABLED 0
#define OPTION_ENABLED  1

/* All parameters are treated the same, as an integer array of values.
 * This macro just reduces the need to repeat the same declaration code
 * over and over (plus this helps to avoid typo bugs).
 */

#define IXGBE_PARAM_INIT { [0 ... IXGBE_MAX_NIC] = OPTION_UNSET }
#ifndef module_param_array
/* Module Parameters are always initialized to -1, so that the driver
 * can tell the difference between no user specified value or the
 * user asking for the default value.
 * The true default values are loaded in when ixgbevf_check_options is called.
 *
 * This is a GCC extension to ANSI C.
 * See the item "Labeled Elements in Initializers" in the section
 * "Extensions to the C Language Family" of the GCC documentation.
 */

#define IXGBE_PARAM(X, desc) \
	static const int __devinitdata X[IXGBE_MAX_NIC+1] = IXGBE_PARAM_INIT; \
	MODULE_PARM(X, "1-" __MODULE_STRING(IXGBE_MAX_NIC) "i"); \
	MODULE_PARM_DESC(X, desc);
#else
#define IXGBE_PARAM(X, desc) \
	static int __devinitdata X[IXGBE_MAX_NIC+1] = IXGBE_PARAM_INIT; \
	static unsigned int num_##X; \
	module_param_array_named(X, X, int, &num_##X, 0); \
	MODULE_PARM_DESC(X, desc);
#endif

#ifdef DEV_HPCAP
	IXGBE_PARAM(Core, "set the starting core to allocate receive on, default -1");
#endif /* DEV_HPCAP */

/* Interrupt Throttle Rate (interrupts/sec)
 *
 * Valid Range: 956-488281 (0=off, 1=dynamic)
 *
 * Default Value: 1
 */
#define DEFAULT_ITR                 1
IXGBE_PARAM(InterruptThrottleRate, "Maximum interrupts per second, per vector, (956-488281, 0=off, 1=dynamic), default 1");
#define MAX_ITR       IXGBE_MAX_INT_RATE
#define MIN_ITR       IXGBE_MIN_INT_RATE

#ifdef DEV_HPCAP
        /* RXQ - The number of RX queues
         *
         * Valid Range: 0-16
         *  - 0 - min(16, num_online_cpus())
         *  - 1-16 - sets the Desc. Q's to the specified value.
         *
         * Default Value: 1
         */
        IXGBE_PARAM(RXQ, "Number of RX queues, default 1. 0 = number of cpus");

        /* TXQ - The number of TX queues
         *
         * Valid Range: 0-16
         *  - 0 - min(16, num_online_cpus())
         *  - 1-16 - sets the Desc. Q's to the specified value.
         *
         * Default Value: 1
         */
        IXGBE_PARAM(TXQ, "Number of TX queues, default 1. 0 = number of cpus");

        /* Mode - working mode
         *
         * Valid Range: 1-3
         *  - 1 - standard ixgbe behaviour
         *  - 2 - high performance RX
         *
         * Default Value: 1
         */
        IXGBE_PARAM(Mode, "RX mode (1=standard ixgbe, 2=high performance RX). Default 1");

        /* Dup - switching duplicates policy
         *
         * Valid Range: 0-1
         *  - 0 - don't check for duplicated packets
         *  - 1 - remove witching duplicates
         *
         *  Default value: 0
         */
        IXGBE_PARAM(Dup, "Dup (0=don't check, 1=remove switching duplicates). Default 0");

        /* Caplen - maximum amount of bytes captured per packet
         *
         * Valid Range: >=0
         *  - 0 - full packet
         *
         * Default Value: 0
         */
        IXGBE_PARAM(Caplen, "Capture length (BYTES). Default 0 (full packet).");
#endif /* DEV_HPCAP */

struct ixgbevf_option {
	enum { enable_option, range_option, list_option } type;
	const char *name;
	const char *err;
	int def;
	union {
		struct { /* range_option info */
			int min;
			int max;
		} r;
		struct { /* list_option info */
			int nr;
			const struct ixgbevf_opt_list {
				int i;
				char *str;
			} *p;
		} l;
	} arg;
};

static int __devinit ixgbevf_validate_option(unsigned int *value,
					     struct ixgbevf_option *opt)
{
	if (*value == OPTION_UNSET) {
		*value = opt->def;
		return 0;
	}

	switch (opt->type) {
	case enable_option:
		switch (*value) {
		case OPTION_ENABLED:
			printk(KERN_INFO "ixgbevf: %s Enabled\n", opt->name);
			return 0;
		case OPTION_DISABLED:
			printk(KERN_INFO "ixgbevf: %s Disabled\n", opt->name);
			return 0;
		}
		break;
	case range_option:
		if (*value >= opt->arg.r.min && *value <= opt->arg.r.max) {
			printk(KERN_INFO "ixgbevf: %s set to %d\n", opt->name, *value);
			return 0;
		}
		break;
	case list_option: {
		int i;
		const struct ixgbevf_opt_list *ent;

		for (i = 0; i < opt->arg.l.nr; i++) {
			ent = &opt->arg.l.p[i];
			if (*value == ent->i) {
				if (ent->str[0] != '\0')
					printk(KERN_INFO "%s\n", ent->str);
				return 0;
			}
		}
	}
		break;
	default:
		BUG();
	}

	printk(KERN_INFO "ixgbevf: Invalid %s specified (%d),  %s\n",
	       opt->name, *value, opt->err);
	*value = opt->def;
	return -1;
}

#define LIST_LEN(l) (sizeof(l) / sizeof(l[0]))

/**
 * ixgbevf_check_options - Range Checking for Command Line Parameters
 * @adapter: board private structure
 *
 * This routine checks all command line parameters for valid user
 * input.  If an invalid value is given, or if no user specified
 * value exists, a default value is used.  The final value is stored
 * in a variable in the adapter structure.
 **/
void __devinit ixgbevf_check_options(struct ixgbevf_adapter *adapter)
{
	int bd = adapter->bd_number;

	if (bd >= IXGBE_MAX_NIC) {
		printk(KERN_NOTICE
		       "Warning: no configuration for board #%d\n", bd);
		printk(KERN_NOTICE "Using defaults for all values\n");
#ifndef module_param_array
		bd = IXGBE_MAX_NIC;
#endif
	}

	{ /* Interrupt Throttling Rate */
		static struct ixgbevf_option opt = {
			.type = range_option,
			.name = "Interrupt Throttling Rate (ints/sec)",
			.err  = "using default of "__MODULE_STRING(DEFAULT_ITR),
			.def  = DEFAULT_ITR,
			.arg  = { .r = { .min = MIN_ITR,
					 .max = MAX_ITR }}
		};

#ifdef module_param_array
		if (num_InterruptThrottleRate > bd) {
#endif
			u32 itr = InterruptThrottleRate[bd];
			switch (itr) {
			case 0:
				DPRINTK(PROBE, INFO, "%s turned off\n",
				        opt.name);
				adapter->rx_itr_setting = 0;
				break;
			case 1:
				DPRINTK(PROBE, INFO, "dynamic interrupt "
					"throttling enabled\n");
				adapter->rx_itr_setting = 1;
				break;
			default:
				ixgbevf_validate_option(&itr, &opt);
				/* the first bit is used as control */
				adapter->rx_itr_setting = (1000000/itr) << 2;
				break;
			}
#ifdef module_param_array
		} else if (opt.def < 2) {
			adapter->rx_itr_setting = opt.def;
		} else {
			adapter->rx_itr_setting = (1000000/opt.def) << 2;
		}
#endif
		adapter->tx_itr_setting = adapter->rx_itr_setting;
	}
#ifdef DEV_HPCAP
                { /* # of RX queues with RSS (RXQ) */
                        static struct ixgbevf_option opt = {
                                .type = range_option,
                                .name = "RX queues (RXQ)",
                                .err  = "using default.",
                                .def  = 1,
                                .arg  = { .r = { .min = 0,
                                                 .max = IXGBEVF_MAX_RSS_INDICES}}
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
                                rxq = min(IXGBEVF_MAX_RSS_INDICES,
                                          (int)num_online_cpus());
                                break;
                        default:
                                ixgbevf_validate_option(&rxq, &opt);
                                break;
                        }
                        //feature[RING_F_RXQ].indices = rxq;
                        //*aflags |= IXGBE_FLAG_RSS_ENABLED;
                }
                { /* # of TX queues (TXQ) */
                        static struct ixgbevf_option opt = {
                                .type = range_option,
                                .name = "TX queues (TXQ)",
                                .err  = "using default.",
                                .def  = 1,
                                .arg  = { .r = { .min = 0,
                                                 .max = IXGBEVF_MAX_RSS_INDICES}}
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
                                txq = min(IXGBEVF_MAX_RSS_INDICES,
                                          (int)num_online_cpus());
                                break;
                        default:
                                ixgbevf_validate_option(&txq, &opt);
                                break;
                        }
                        //feature[RING_F_TXQ].indices = txq;
                }
	        { /* CORE assignment */
	                static struct ixgbevf_option opt = {
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
	                        ixgbevf_validate_option((uint *)&core_param, &opt);
	
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
        	        static struct ixgbevf_option opt = {
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
	                        ixgbevf_validate_option((uint *)&mode_param, &opt);
	                #ifdef module_param_array
	                }
	                #endif
	
	                adapter->work_mode = mode_param;
	                printk("PARAM: Adapter %s mode = %d\n",adapter->netdev->name, adapter->work_mode);
	        }
		{ /* Dup assignment */
	                static struct ixgbevf_option opt = {
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
	                        ixgbevf_validate_option((uint *)&dup_param, &opt);
	                #ifdef module_param_array
	                }
	                #endif
	                adapter->dup_mode = dup_param;
	                printk("PARAM: Adapter %s dup = %d\n",adapter->netdev->name, adapter->dup_mode);
	        }
		{ /* Caplen assignment */
	                static struct ixgbevf_option opt = {
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
	                        ixgbevf_validate_option((uint *)&caplen_param, &opt);
	                #ifdef module_param_array
	                }
	                #endif
	
	                adapter->caplen = caplen_param;
	                printk("PARAM: Adapter %s Caplen = %d\n",adapter->netdev->name, adapter->caplen);
	        }
#endif /* DEV_HPCAP */
}
