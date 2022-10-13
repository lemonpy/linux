// SPDX-License-Identifier: GPL-2.0-only
/*
 * Intel PCH/PCU SPI flash driver.
 *
 * Copyright (C) 2016 - 2022, Intel Corporation
 * Author: Mika Westerberg <mika.westerberg@linux.intel.com>
 */

#include <linux/iopoll.h>

#include "spi-intel.h"
#include "spi-intel-common.h"
#include "spi-intel-swseq.h"

bool mem_op_supported_on_spi_locked(const struct intel_spi *ispi,
				    const struct spi_mem_op *op)
{
	int i;

	/* Check if it is in the locked opcodes list */
	for (i = 0; i < ARRAY_SIZE(ispi->opcodes); i++) {
		if (ispi->opcodes[i] == op->cmd.opcode)
			return true;
	}

	dev_dbg(ispi->dev, "%#x not supported\n", op->cmd.opcode);
	return false;
}
EXPORT_SYMBOL(mem_op_supported_on_spi_locked);

inline bool is_swseq_enabled(void)
{
	return true;
}
EXPORT_SYMBOL(is_swseq_enabled);

int handle_swseq_wren(struct intel_spi *ispi)
{
	u16 preop;
	const u8 opcode = SPINOR_OP_WREN;

	if (!ispi->swseq_reg)
		return 0;

	preop = readw(ispi->sregs + PREOP_OPTYPE);
	if ((preop & 0xff) != SPINOR_OP_WREN && (preop >> 8) != SPINOR_OP_WREN) {
		if (ispi->locked)
			return -EINVAL;
		writel(opcode, ispi->sregs + PREOP_OPTYPE);
	}

	/*
	* This enables atomic sequence on next SW sycle. Will
	* be cleared after next operation.
	*/
	ispi->atomic_preopcode = opcode;
	return 0;
}
EXPORT_SYMBOL(handle_swseq_wren);

static int intel_spi_wait_sw_busy(const struct intel_spi *ispi)
{
	u32 val;

	return readl_poll_timeout(ispi->sregs + SSFSTS_CTL, val,
				  !(val & SSFSTS_CTL_SCIP), 0,
				  INTEL_SPI_TIMEOUT * 1000);
}

static int intel_spi_opcode_index(const struct intel_spi *ispi, u8 opcode, int optype)
{
	int i;
	int preop;

	if (ispi->locked) {
		for (i = 0; i < ARRAY_SIZE(ispi->opcodes); i++)
			if (ispi->opcodes[i] == opcode)
				return i;

		return -EINVAL;
	}

	/* The lock is off, so just use index 0 */
	writel(opcode, ispi->sregs + OPMENU0);
	preop = readw(ispi->sregs + PREOP_OPTYPE);
	writel(optype << 16 | preop, ispi->sregs + PREOP_OPTYPE);

	return 0;
}

int intel_spi_sw_cycle(struct intel_spi *ispi, u8 opcode, size_t len,
		       int optype)
{
	u32 val = 0, status;
	u8 atomic_preopcode;
	int ret;

	ret = intel_spi_opcode_index(ispi, opcode, optype);
	if (ret < 0)
		return ret;

	if (len > INTEL_SPI_FIFO_SZ)
		return -EINVAL;

	/*
	 * Always clear it after each SW sequencer operation regardless
	 * of whether it is successful or not.
	 */
	atomic_preopcode = ispi->atomic_preopcode;
	ispi->atomic_preopcode = 0;

	/* Only mark 'Data Cycle' bit when there is data to be transferred */
	if (len > 0)
		val = ((len - 1) << SSFSTS_CTL_DBC_SHIFT) | SSFSTS_CTL_DS;
	val |= ret << SSFSTS_CTL_COP_SHIFT;
	val |= SSFSTS_CTL_FCERR | SSFSTS_CTL_FDONE;
	val |= SSFSTS_CTL_SCGO;
	if (atomic_preopcode) {
		u16 preop;

		switch (optype) {
		case OPTYPE_WRITE_NO_ADDR:
		case OPTYPE_WRITE_WITH_ADDR:
			/* Pick matching preopcode for the atomic sequence */
			preop = readw(ispi->sregs + PREOP_OPTYPE);
			if ((preop & 0xff) == atomic_preopcode)
				; /* Do nothing */
			else if ((preop >> 8) == atomic_preopcode)
				val |= SSFSTS_CTL_SPOP;
			else
				return -EINVAL;

			/* Enable atomic sequence */
			val |= SSFSTS_CTL_ACS;
			break;

		default:
			return -EINVAL;
		}
	}
	writel(val, ispi->sregs + SSFSTS_CTL);

	ret = intel_spi_wait_sw_busy(ispi);
	if (ret)
		return ret;

	status = readl(ispi->sregs + SSFSTS_CTL);
	if (status & SSFSTS_CTL_FCERR)
		return -EIO;
	else if (status & SSFSTS_CTL_AEL)
		return -EACCES;

	return 0;
}
EXPORT_SYMBOL(intel_spi_sw_cycle);

void disable_smi_generation(const struct intel_spi *ispi)
{
    u32 val;
    val = readl(ispi->sregs + SSFSTS_CTL);
    val &= ~SSFSTS_CTL_FSMIE;
    writel(val, ispi->sregs + SSFSTS_CTL);
}
EXPORT_SYMBOL(disable_smi_generation);

void populate_opmenus(struct intel_spi *ispi, u32 *opmenu0, u32 *opmenu1)
{
    unsigned int i;
    *opmenu0 = readl(ispi->sregs + OPMENU0);
    *opmenu1 = readl(ispi->sregs + OPMENU1);

    if (*opmenu0 && *opmenu1) {
            for (i = 0; i < ARRAY_SIZE(ispi->opcodes) / 2; i++) {
                ispi->opcodes[i] = *opmenu0 >> i * 8;
                ispi->opcodes[i + 4] = *opmenu1 >> i * 8;
            }
    }
}
EXPORT_SYMBOL(populate_opmenus);

MODULE_LICENSE("GPL v2");
