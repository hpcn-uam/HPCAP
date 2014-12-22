
IXGBE_PARAM(Core, "set the starting core to allocate receive on, default -1");

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
#ifndef REMOVE_DUPS
IXGBE_PARAM(Dup, "Dup (0=don't check, 1=remove switching duplicates). Default 0");
#else
//#define CADENA_DUP "Dup (0=don't check, 1=remove switching duplicates). Default 0 [CHECK_LEN " DUP_CHECK_LEN ", WINDOW_SIZE " DUP_WINDOW_SIZE ", WINDOW_LEVELS " DUP_WINDOW_LEVELS
#define CADENA_DUP "Dup (0=don't check, 1=remove switching duplicates). Default 0 [CHECK_LEN " SCL ", WINDOW_SIZE " SWS ", WINDOW_LEVELS " SWL ", TIME_WINDOW " STW "]"
IXGBE_PARAM(Dup, CADENA_DUP);
#endif

/* Pages - Amount of pages for the interfaces's kernel buffer in hpcap mode
 *
 * Valid Range: >=1
 *
 *  Default value: 0
 */
IXGBE_PARAM(Pages, "Pages (>=1). Amount of pages for the interfaces's kernel buffer in hpcap mode");

/* Caplen - maximum amount of bytes captured per packet
 *
 * Valid Range: >=0
 *  - 0 - full packet
 *
 * Default Value: 0
 */
IXGBE_PARAM(Caplen, "Capture length (BYTES). Default 0 (full packet).");

