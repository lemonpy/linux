// SPDX-License-Identifier: GPL-2.0-only
/*
 * Intel PCH/PCU SPI flash driver.
 *
 * Copyright (C) 2016 - 2022, Intel Corporation
 * Author: Mika Westerberg <mika.westerberg@linux.intel.com>
 */

#include <linux/iopoll.h>
#include <linux/module.h>

#include <linux/mtd/partitions.h>
#include <linux/mtd/spi-nor.h>

#include <linux/spi/flash.h>
#include <linux/spi/spi.h>
#include <linux/spi/spi-mem.h>

#include "spi-intel.h"
#include "spi-intel-common.h"
#include "spi-intel-swseq.h"

struct intel_spi_mem_op {
	struct spi_mem_op mem_op;
	u32 replacement_op;
	int (*exec_op)(struct intel_spi *ispi,
		       const struct spi_mem *mem,
		       const struct intel_spi_mem_op *iop,
		       const struct spi_mem_op *op);
};

static bool writeable;
module_param(writeable, bool, 0);
MODULE_PARM_DESC(writeable, "Enable write access to SPI flash chip (default=0)");

static void intel_spi_dump_regs(struct intel_spi *ispi)
{
	u32 value;
	int i;

	dev_dbg(ispi->dev, "BFPREG=0x%08x\n", readl(ispi->base + BFPREG));

	value = readl(ispi->base + HSFSTS_CTL);
	dev_dbg(ispi->dev, "HSFSTS_CTL=0x%08x\n", value);
	if (value & HSFSTS_CTL_FLOCKDN)
		dev_dbg(ispi->dev, "-> Locked\n");

	dev_dbg(ispi->dev, "FADDR=0x%08x\n", readl(ispi->base + FADDR));
	dev_dbg(ispi->dev, "DLOCK=0x%08x\n", readl(ispi->base + DLOCK));

	for (i = 0; i < 16; i++)
		dev_dbg(ispi->dev, "FDATA(%d)=0x%08x\n",
			i, readl(ispi->base + FDATA(i)));

	dev_dbg(ispi->dev, "FRACC=0x%08x\n", readl(ispi->base + FRACC));

	for (i = 0; i < ispi->nregions; i++)
		dev_dbg(ispi->dev, "FREG(%d)=0x%08x\n", i,
			readl(ispi->base + FREG(i)));
	for (i = 0; i < ispi->pr_num; i++)
		dev_dbg(ispi->dev, "PR(%d)=0x%08x\n", i,
			readl(ispi->pregs + PR(i)));

	if (ispi->sregs) {
		value = readl(ispi->sregs + SSFSTS_CTL);
		dev_dbg(ispi->dev, "SSFSTS_CTL=0x%08x\n", value);
		dev_dbg(ispi->dev, "PREOP_OPTYPE=0x%08x\n",
			readl(ispi->sregs + PREOP_OPTYPE));
		dev_dbg(ispi->dev, "OPMENU0=0x%08x\n",
			readl(ispi->sregs + OPMENU0));
		dev_dbg(ispi->dev, "OPMENU1=0x%08x\n",
			readl(ispi->sregs + OPMENU1));
	}

	dev_dbg(ispi->dev, "LVSCC=0x%08x\n", readl(ispi->base + LVSCC));
	dev_dbg(ispi->dev, "UVSCC=0x%08x\n", readl(ispi->base + UVSCC));

	dev_dbg(ispi->dev, "Protected regions:\n");
	for (i = 0; i < ispi->pr_num; i++) {
		u32 base, limit;

		value = readl(ispi->pregs + PR(i));
		if (!(value & (PR_WPE | PR_RPE)))
			continue;

		limit = (value & PR_LIMIT_MASK) >> PR_LIMIT_SHIFT;
		base = value & PR_BASE_MASK;

		dev_dbg(ispi->dev, " %02d base: 0x%08x limit: 0x%08x [%c%c]\n",
			i, base << 12, (limit << 12) | 0xfff,
			value & PR_WPE ? 'W' : '.', value & PR_RPE ? 'R' : '.');
	}

	dev_dbg(ispi->dev, "Flash regions:\n");
	for (i = 0; i < ispi->nregions; i++) {
		u32 region, base, limit;

		region = readl(ispi->base + FREG(i));
		base = region & FREG_BASE_MASK;
		limit = (region & FREG_LIMIT_MASK) >> FREG_LIMIT_SHIFT;

		if (base >= limit || (i > 0 && limit == 0))
			dev_dbg(ispi->dev, " %02d disabled\n", i);
		else
			dev_dbg(ispi->dev, " %02d base: 0x%08x limit: 0x%08x\n",
				i, base << 12, (limit << 12) | 0xfff);
	}

	dev_dbg(ispi->dev, "Using %cW sequencer for register access\n",
		ispi->swseq_reg && ispi->swseq_enabled ? 'S' : 'H');
	dev_dbg(ispi->dev, "Using %cW sequencer for erase operation\n",
		ispi->swseq_erase && ispi->swseq_enabled ? 'S' : 'H');

	if (!ispi->swseq_enabled)
		dev_dbg(ispi->dev, "SW sequencer is disabled for all operations\n");
}

/* Reads max INTEL_SPI_FIFO_SZ bytes from the device fifo */
static int intel_spi_read_block(struct intel_spi *ispi, void *buf, size_t size)
{
	size_t bytes;
	int i = 0;

	if (size > INTEL_SPI_FIFO_SZ)
		return -EINVAL;

	while (size > 0) {
		bytes = min_t(size_t, size, 4);
		memcpy_fromio(buf, ispi->base + FDATA(i), bytes);
		size -= bytes;
		buf += bytes;
		i++;
	}

	return 0;
}

/* Writes max INTEL_SPI_FIFO_SZ bytes to the device fifo */
static int intel_spi_write_block(struct intel_spi *ispi, const void *buf,
				 size_t size)
{
	size_t bytes;
	int i = 0;

	if (size > INTEL_SPI_FIFO_SZ)
		return -EINVAL;

	while (size > 0) {
		bytes = min_t(size_t, size, 4);
		memcpy_toio(ispi->base + FDATA(i), buf, bytes);
		size -= bytes;
		buf += bytes;
		i++;
	}

	return 0;
}

static int intel_spi_wait_hw_busy(struct intel_spi *ispi)
{
	u32 val;

	return readl_poll_timeout(ispi->base + HSFSTS_CTL, val,
				  !(val & HSFSTS_CTL_SCIP), 0,
				  INTEL_SPI_TIMEOUT * 1000);
}

static bool intel_spi_set_writeable(struct intel_spi *ispi)
{
	if (!ispi->info->set_writeable)
		return false;

	return ispi->info->set_writeable(ispi->base, ispi->info->data);
}

static int intel_spi_hw_cycle(struct intel_spi *ispi, u8 opcode, size_t len)
{
	u32 val, status;
	int ret;

	val = readl(ispi->base + HSFSTS_CTL);
	val &= ~(HSFSTS_CTL_FCYCLE_MASK | HSFSTS_CTL_FDBC_MASK);

	switch (opcode) {
	case SPINOR_OP_RDID:
		val |= HSFSTS_CTL_FCYCLE_RDID;
		break;
	case SPINOR_OP_WRSR:
		val |= HSFSTS_CTL_FCYCLE_WRSR;
		break;
	case SPINOR_OP_RDSR:
		val |= HSFSTS_CTL_FCYCLE_RDSR;
		break;
	default:
		return -EINVAL;
	}

	if (len > INTEL_SPI_FIFO_SZ)
		return -EINVAL;

	val |= (len - 1) << HSFSTS_CTL_FDBC_SHIFT;
	val |= HSFSTS_CTL_FCERR | HSFSTS_CTL_FDONE;
	val |= HSFSTS_CTL_FGO;
	writel(val, ispi->base + HSFSTS_CTL);

	ret = intel_spi_wait_hw_busy(ispi);
	if (ret)
		return ret;

	status = readl(ispi->base + HSFSTS_CTL);
	if (status & HSFSTS_CTL_FCERR)
		return -EIO;
	else if (status & HSFSTS_CTL_AEL)
		return -EACCES;

	return 0;
}

static u32 intel_spi_chip_addr(const struct intel_spi *ispi,
			       const struct spi_mem *mem)
{
	/* Pick up the correct start address */
	if (!mem)
		return 0;
	return mem->spi->chip_select == 1 ? ispi->chip0_size : 0;
}

static int intel_spi_read_reg(struct intel_spi *ispi, const struct spi_mem *mem,
			      const struct intel_spi_mem_op *iop,
			      const struct spi_mem_op *op)
{
	size_t nbytes = op->data.nbytes;
	u8 opcode = op->cmd.opcode;
	int ret;

	writel(intel_spi_chip_addr(ispi, mem), ispi->base + FADDR);

	if (ispi->swseq_reg && ispi->swseq_enabled)
		ret = intel_spi_sw_cycle(ispi, opcode, nbytes,
					 OPTYPE_READ_NO_ADDR);
	else
		ret = intel_spi_hw_cycle(ispi, opcode, nbytes);

	if (ret)
		return ret;

	return intel_spi_read_block(ispi, op->data.buf.in, nbytes);
}

static int intel_spi_write_reg(struct intel_spi *ispi, const struct spi_mem *mem,
			       const struct intel_spi_mem_op *iop,
			       const struct spi_mem_op *op)
{
	size_t nbytes = op->data.nbytes;
	u8 opcode = op->cmd.opcode;
	int ret;

	/*
	 * This is handled with atomic operation and preop code in Intel
	 * controller so we only verify that it is available. If the
	 * controller is not locked, program the opcode to the PREOP
	 * register for later use.
	 *
	 * When hardware sequencer is used there is no need to program
	 * any opcodes (it handles them automatically as part of a command).
	 */
	if (opcode == SPINOR_OP_WREN)
		return handle_swseq_wren(ispi);

	/*
	 * We hope that HW sequencer will do the right thing automatically and
	 * with the SW sequencer we cannot use preopcode anyway, so just ignore
	 * the Write Disable operation and pretend it was completed
	 * successfully.
	 */
	if (opcode == SPINOR_OP_WRDI)
		return 0;

	writel(intel_spi_chip_addr(ispi, mem), ispi->base + FADDR);

	/* Write the value beforehand */
	ret = intel_spi_write_block(ispi, op->data.buf.out, nbytes);
	if (ret)
		return ret;

	if (ispi->swseq_reg && ispi->swseq_enabled)
		return intel_spi_sw_cycle(ispi, opcode, nbytes,
					  OPTYPE_WRITE_NO_ADDR);
	return intel_spi_hw_cycle(ispi, opcode, nbytes);
}

static int intel_spi_read(struct intel_spi *ispi, const struct spi_mem *mem,
			  const struct intel_spi_mem_op *iop,
			  const struct spi_mem_op *op)
{
	u32 addr = intel_spi_chip_addr(ispi, mem) + op->addr.val;
	size_t block_size, nbytes = op->data.nbytes;
	void *read_buf = op->data.buf.in;
	u32 val, status;
	int ret;

	/*
	 * Atomic sequence is not expected with HW sequencer reads. Make
	 * sure it is cleared regardless.
	 */
	if (WARN_ON_ONCE(ispi->atomic_preopcode))
		ispi->atomic_preopcode = 0;

	while (nbytes > 0) {
		block_size = min_t(size_t, nbytes, INTEL_SPI_FIFO_SZ);

		/* Read cannot cross 4K boundary */
		block_size = min_t(loff_t, addr + block_size,
				   round_up(addr + 1, SZ_4K)) - addr;

		writel(addr, ispi->base + FADDR);

		val = readl(ispi->base + HSFSTS_CTL);
		val &= ~(HSFSTS_CTL_FDBC_MASK | HSFSTS_CTL_FCYCLE_MASK);
		val |= HSFSTS_CTL_AEL | HSFSTS_CTL_FCERR | HSFSTS_CTL_FDONE;
		val |= (block_size - 1) << HSFSTS_CTL_FDBC_SHIFT;
		val |= HSFSTS_CTL_FCYCLE_READ;
		val |= HSFSTS_CTL_FGO;
		writel(val, ispi->base + HSFSTS_CTL);

		ret = intel_spi_wait_hw_busy(ispi);
		if (ret)
			return ret;

		status = readl(ispi->base + HSFSTS_CTL);
		if (status & HSFSTS_CTL_FCERR)
			ret = -EIO;
		else if (status & HSFSTS_CTL_AEL)
			ret = -EACCES;

		if (ret < 0) {
			dev_err(ispi->dev, "read error: %x: %#x\n", addr, status);
			return ret;
		}

		ret = intel_spi_read_block(ispi, read_buf, block_size);
		if (ret)
			return ret;

		nbytes -= block_size;
		addr += block_size;
		read_buf += block_size;
	}

	return 0;
}

static int intel_spi_write(struct intel_spi *ispi, const struct spi_mem *mem,
			   const struct intel_spi_mem_op *iop,
			   const struct spi_mem_op *op)
{
	u32 addr = intel_spi_chip_addr(ispi, mem) + op->addr.val;
	size_t block_size, nbytes = op->data.nbytes;
	const void *write_buf = op->data.buf.out;
	u32 val, status;
	int ret;

	/* Not needed with HW sequencer write, make sure it is cleared */
	ispi->atomic_preopcode = 0;

	while (nbytes > 0) {
		block_size = min_t(size_t, nbytes, INTEL_SPI_FIFO_SZ);

		/* Write cannot cross 4K boundary */
		block_size = min_t(loff_t, addr + block_size,
				   round_up(addr + 1, SZ_4K)) - addr;

		writel(addr, ispi->base + FADDR);

		val = readl(ispi->base + HSFSTS_CTL);
		val &= ~(HSFSTS_CTL_FDBC_MASK | HSFSTS_CTL_FCYCLE_MASK);
		val |= HSFSTS_CTL_AEL | HSFSTS_CTL_FCERR | HSFSTS_CTL_FDONE;
		val |= (block_size - 1) << HSFSTS_CTL_FDBC_SHIFT;
		val |= HSFSTS_CTL_FCYCLE_WRITE;

		ret = intel_spi_write_block(ispi, write_buf, block_size);
		if (ret) {
			dev_err(ispi->dev, "failed to write block\n");
			return ret;
		}

		/* Start the write now */
		val |= HSFSTS_CTL_FGO;
		writel(val, ispi->base + HSFSTS_CTL);

		ret = intel_spi_wait_hw_busy(ispi);
		if (ret) {
			dev_err(ispi->dev, "timeout\n");
			return ret;
		}

		status = readl(ispi->base + HSFSTS_CTL);
		if (status & HSFSTS_CTL_FCERR)
			ret = -EIO;
		else if (status & HSFSTS_CTL_AEL)
			ret = -EACCES;

		if (ret < 0) {
			dev_err(ispi->dev, "write error: %x: %#x\n", addr, status);
			return ret;
		}

		nbytes -= block_size;
		addr += block_size;
		write_buf += block_size;
	}

	return 0;
}

static int intel_spi_erase(struct intel_spi *ispi, const struct spi_mem *mem,
			   const struct intel_spi_mem_op *iop,
			   const struct spi_mem_op *op)
{
	u32 addr = intel_spi_chip_addr(ispi, mem) + op->addr.val;
	u8 opcode = op->cmd.opcode;
	u32 val, status;
	int ret;

	writel(addr, ispi->base + FADDR);

	/*
	 * If swseq_erase is true, it means that we cannot erase using
	 * HW sequencer.
	 */
	if (ispi->swseq_erase && ispi->swseq_enabled)
		return intel_spi_sw_cycle(ispi, opcode, 0,
					  OPTYPE_WRITE_WITH_ADDR);

	/* Not needed with HW sequencer erase, make sure it is cleared */
	ispi->atomic_preopcode = 0;

	val = readl(ispi->base + HSFSTS_CTL);
	val &= ~(HSFSTS_CTL_FDBC_MASK | HSFSTS_CTL_FCYCLE_MASK);
	val |= HSFSTS_CTL_AEL | HSFSTS_CTL_FCERR | HSFSTS_CTL_FDONE;
	val |= HSFSTS_CTL_FGO;
	val |= iop->replacement_op;
	writel(val, ispi->base + HSFSTS_CTL);

	ret = intel_spi_wait_hw_busy(ispi);
	if (ret)
		return ret;

	status = readl(ispi->base + HSFSTS_CTL);
	if (status & HSFSTS_CTL_FCERR)
		return -EIO;
	if (status & HSFSTS_CTL_AEL)
		return -EACCES;

	return 0;
}

static bool intel_spi_cmp_mem_op(const struct intel_spi_mem_op *iop,
				 const struct spi_mem_op *op)
{
	if (iop->mem_op.cmd.nbytes != op->cmd.nbytes ||
	    iop->mem_op.cmd.buswidth != op->cmd.buswidth ||
	    iop->mem_op.cmd.dtr != op->cmd.dtr ||
	    iop->mem_op.cmd.opcode != op->cmd.opcode)
		return false;

	if (iop->mem_op.addr.nbytes != op->addr.nbytes ||
	    iop->mem_op.addr.dtr != op->addr.dtr)
		return false;

	if (iop->mem_op.data.dir != op->data.dir ||
	    iop->mem_op.data.dtr != op->data.dtr)
		return false;

	if (iop->mem_op.data.dir != SPI_MEM_NO_DATA) {
		if (iop->mem_op.data.buswidth != op->data.buswidth)
			return false;
	}

	return true;
}

static const struct intel_spi_mem_op *
intel_spi_match_mem_op(struct intel_spi *ispi, const struct spi_mem_op *op)
{
	const struct intel_spi_mem_op *iop;

	for (iop = ispi->mem_ops; iop->mem_op.cmd.opcode; iop++) {
		if (intel_spi_cmp_mem_op(iop, op))
			break;
	}

	return iop->mem_op.cmd.opcode ? iop : NULL;
}

static bool intel_spi_supports_mem_op(struct spi_mem *mem,
				      const struct spi_mem_op *op)
{
	struct intel_spi *ispi = spi_master_get_devdata(mem->spi->master);
	const struct intel_spi_mem_op *iop;

	iop = intel_spi_match_mem_op(ispi, op);
	if (!iop) {
		dev_dbg(ispi->dev, "%#x not supported\n", op->cmd.opcode);
		return false;
	}

	/*
	 * For software sequencer check that the opcode is actually
	 * present in the opmenu if it is locked.
	 */
	if (ispi->swseq_reg && ispi->locked && ispi->swseq_enabled)
		return mem_op_supported_on_spi_locked(ispi, op);

	return true;
}

static int intel_spi_exec_mem_op(struct spi_mem *mem, const struct spi_mem_op *op)
{
	struct intel_spi *ispi = spi_master_get_devdata(mem->spi->master);
	const struct intel_spi_mem_op *iop;

	iop = intel_spi_match_mem_op(ispi, op);
	if (!iop)
		return -EOPNOTSUPP;

	return iop->exec_op(ispi, mem, iop, op);
}

static const char *intel_spi_get_name(struct spi_mem *mem)
{
	const struct intel_spi *ispi = spi_master_get_devdata(mem->spi->master);

	/*
	 * Return name of the flash controller device to be compatible
	 * with the MTD version.
	 */
	return dev_name(ispi->dev);
}

static int intel_spi_dirmap_create(struct spi_mem_dirmap_desc *desc)
{
	struct intel_spi *ispi = spi_master_get_devdata(desc->mem->spi->master);
	const struct intel_spi_mem_op *iop;

	iop = intel_spi_match_mem_op(ispi, &desc->info.op_tmpl);
	if (!iop)
		return -EOPNOTSUPP;

	desc->priv = (void *)iop;
	return 0;
}

static ssize_t intel_spi_dirmap_read(struct spi_mem_dirmap_desc *desc, u64 offs,
				     size_t len, void *buf)
{
	struct intel_spi *ispi = spi_master_get_devdata(desc->mem->spi->master);
	const struct intel_spi_mem_op *iop = desc->priv;
	struct spi_mem_op op = desc->info.op_tmpl;
	int ret;

	/* Fill in the gaps */
	op.addr.val = offs;
	op.data.nbytes = len;
	op.data.buf.in = buf;

	ret = iop->exec_op(ispi, desc->mem, iop, &op);
	return ret ? ret : len;
}

static ssize_t intel_spi_dirmap_write(struct spi_mem_dirmap_desc *desc, u64 offs,
				      size_t len, const void *buf)
{
	struct intel_spi *ispi = spi_master_get_devdata(desc->mem->spi->master);
	const struct intel_spi_mem_op *iop = desc->priv;
	struct spi_mem_op op = desc->info.op_tmpl;
	int ret;

	op.addr.val = offs;
	op.data.nbytes = len;
	op.data.buf.out = buf;

	ret = iop->exec_op(ispi, desc->mem, iop, &op);
	return ret ? ret : len;
}

static const struct spi_controller_mem_ops intel_spi_mem_ops = {
	.supports_op = intel_spi_supports_mem_op,
	.exec_op = intel_spi_exec_mem_op,
	.get_name = intel_spi_get_name,
	.dirmap_create = intel_spi_dirmap_create,
	.dirmap_read = intel_spi_dirmap_read,
	.dirmap_write = intel_spi_dirmap_write,
};

#define INTEL_SPI_OP_ADDR(__nbytes)					\
	{								\
		.nbytes = __nbytes,					\
	}

#define INTEL_SPI_OP_NO_DATA						\
	{								\
		.dir = SPI_MEM_NO_DATA,					\
	}

#define INTEL_SPI_OP_DATA_IN(__buswidth)				\
	{								\
		.dir = SPI_MEM_DATA_IN,					\
		.buswidth = __buswidth,					\
	}

#define INTEL_SPI_OP_DATA_OUT(__buswidth)				\
	{								\
		.dir = SPI_MEM_DATA_OUT,				\
		.buswidth = __buswidth,					\
	}

#define INTEL_SPI_MEM_OP(__cmd, __addr, __data, __exec_op)		\
	{								\
		.mem_op = {						\
			.cmd = __cmd,					\
			.addr = __addr,					\
			.data = __data,					\
		},							\
		.exec_op = __exec_op,					\
	}

#define INTEL_SPI_MEM_OP_REPL(__cmd, __addr, __data, __exec_op, __repl)	\
	{								\
		.mem_op = {						\
			.cmd = __cmd,					\
			.addr = __addr,					\
			.data = __data,					\
		},							\
		.exec_op = __exec_op,					\
		.replacement_op = __repl,				\
	}

/*
 * The controller handles pretty much everything internally based on the
 * SFDP data but we want to make sure we only support the operations
 * actually possible. Only check buswidth and transfer direction, the
 * core validates data.
 */
#define INTEL_SPI_GENERIC_OPS						\
	/* Status register operations */				\
	INTEL_SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_RDID, 1),		\
			 SPI_MEM_OP_NO_ADDR,				\
			 INTEL_SPI_OP_DATA_IN(1),			\
			 intel_spi_read_reg),				\
	INTEL_SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_RDSR, 1),		\
			 SPI_MEM_OP_NO_ADDR,				\
			 INTEL_SPI_OP_DATA_IN(1),			\
			 intel_spi_read_reg),				\
	INTEL_SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_WRSR, 1),		\
			 SPI_MEM_OP_NO_ADDR,				\
			 INTEL_SPI_OP_DATA_OUT(1),			\
			 intel_spi_write_reg),				\
	/* Normal read */						\
	INTEL_SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_READ, 1),		\
			 INTEL_SPI_OP_ADDR(3),				\
			 INTEL_SPI_OP_DATA_IN(1),			\
			 intel_spi_read),				\
	INTEL_SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_READ, 1),		\
			 INTEL_SPI_OP_ADDR(3),				\
			 INTEL_SPI_OP_DATA_IN(2),			\
			 intel_spi_read),				\
	INTEL_SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_READ, 1),		\
			 INTEL_SPI_OP_ADDR(3),				\
			 INTEL_SPI_OP_DATA_IN(4),			\
			 intel_spi_read),				\
	INTEL_SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_READ, 1),		\
			 INTEL_SPI_OP_ADDR(4),				\
			 INTEL_SPI_OP_DATA_IN(1),			\
			 intel_spi_read),				\
	INTEL_SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_READ, 1),		\
			 INTEL_SPI_OP_ADDR(4),				\
			 INTEL_SPI_OP_DATA_IN(2),			\
			 intel_spi_read),				\
	INTEL_SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_READ, 1),		\
			 INTEL_SPI_OP_ADDR(4),				\
			 INTEL_SPI_OP_DATA_IN(4),			\
			 intel_spi_read),				\
	/* Fast read */							\
	INTEL_SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_READ_FAST, 1),	\
			 INTEL_SPI_OP_ADDR(3),				\
			 INTEL_SPI_OP_DATA_IN(1),			\
			 intel_spi_read),				\
	INTEL_SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_READ_FAST, 1),	\
			 INTEL_SPI_OP_ADDR(3),				\
			 INTEL_SPI_OP_DATA_IN(2),			\
			 intel_spi_read),				\
	INTEL_SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_READ_FAST, 1),	\
			 INTEL_SPI_OP_ADDR(3),				\
			 INTEL_SPI_OP_DATA_IN(4),			\
			 intel_spi_read),				\
	INTEL_SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_READ_FAST, 1),	\
			 INTEL_SPI_OP_ADDR(4),				\
			 INTEL_SPI_OP_DATA_IN(1),			\
			 intel_spi_read),				\
	INTEL_SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_READ_FAST, 1),	\
			 INTEL_SPI_OP_ADDR(4),				\
			 INTEL_SPI_OP_DATA_IN(2),			\
			 intel_spi_read),				\
	INTEL_SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_READ_FAST, 1),	\
			 INTEL_SPI_OP_ADDR(4),				\
			 INTEL_SPI_OP_DATA_IN(4),			\
			 intel_spi_read),				\
	/* Read with 4-byte address opcode */				\
	INTEL_SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_READ_4B, 1),		\
			 INTEL_SPI_OP_ADDR(4),				\
			 INTEL_SPI_OP_DATA_IN(1),			\
			 intel_spi_read),				\
	INTEL_SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_READ_4B, 1),		\
			 INTEL_SPI_OP_ADDR(4),				\
			 INTEL_SPI_OP_DATA_IN(2),			\
			 intel_spi_read),				\
	INTEL_SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_READ_4B, 1),		\
			 INTEL_SPI_OP_ADDR(4),				\
			 INTEL_SPI_OP_DATA_IN(4),			\
			 intel_spi_read),				\
	/* Fast read with 4-byte address opcode */			\
	INTEL_SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_READ_FAST_4B, 1),	\
			 INTEL_SPI_OP_ADDR(4),				\
			 INTEL_SPI_OP_DATA_IN(1),			\
			 intel_spi_read),				\
	INTEL_SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_READ_FAST_4B, 1),	\
			 INTEL_SPI_OP_ADDR(4),				\
			 INTEL_SPI_OP_DATA_IN(2),			\
			 intel_spi_read),				\
	INTEL_SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_READ_FAST_4B, 1),	\
			 INTEL_SPI_OP_ADDR(4),				\
			 INTEL_SPI_OP_DATA_IN(4),			\
			 intel_spi_read),				\
	/* Write operations */						\
	INTEL_SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_PP, 1),		\
			 INTEL_SPI_OP_ADDR(3),				\
			 INTEL_SPI_OP_DATA_OUT(1),			\
			 intel_spi_write),				\
	INTEL_SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_PP, 1),		\
			 INTEL_SPI_OP_ADDR(4),				\
			 INTEL_SPI_OP_DATA_OUT(1),			\
			 intel_spi_write),				\
	INTEL_SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_PP_4B, 1),		\
			 INTEL_SPI_OP_ADDR(4),				\
			 INTEL_SPI_OP_DATA_OUT(1),			\
			 intel_spi_write),				\
	INTEL_SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_WREN, 1),		\
			 SPI_MEM_OP_NO_ADDR,				\
			 SPI_MEM_OP_NO_DATA,				\
			 intel_spi_write_reg),				\
	INTEL_SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_WRDI, 1),		\
			 SPI_MEM_OP_NO_ADDR,				\
			 SPI_MEM_OP_NO_DATA,				\
			 intel_spi_write_reg),				\
	/* Erase operations */						\
	INTEL_SPI_MEM_OP_REPL(SPI_MEM_OP_CMD(SPINOR_OP_BE_4K, 1),	\
			      INTEL_SPI_OP_ADDR(3),			\
			      SPI_MEM_OP_NO_DATA,			\
			      intel_spi_erase,				\
			      HSFSTS_CTL_FCYCLE_ERASE),			\
	INTEL_SPI_MEM_OP_REPL(SPI_MEM_OP_CMD(SPINOR_OP_BE_4K, 1),	\
			      INTEL_SPI_OP_ADDR(4),			\
			      SPI_MEM_OP_NO_DATA,			\
			      intel_spi_erase,				\
			      HSFSTS_CTL_FCYCLE_ERASE),			\
	INTEL_SPI_MEM_OP_REPL(SPI_MEM_OP_CMD(SPINOR_OP_BE_4K_4B, 1),	\
			      INTEL_SPI_OP_ADDR(4),			\
			      SPI_MEM_OP_NO_DATA,			\
			      intel_spi_erase,				\
			      HSFSTS_CTL_FCYCLE_ERASE)			\

static const struct intel_spi_mem_op generic_mem_ops[] = {
	INTEL_SPI_GENERIC_OPS,
	{ },
};

static const struct intel_spi_mem_op erase_64k_mem_ops[] = {
	INTEL_SPI_GENERIC_OPS,
	/* 64k sector erase operations */
	INTEL_SPI_MEM_OP_REPL(SPI_MEM_OP_CMD(SPINOR_OP_SE, 1),
			      INTEL_SPI_OP_ADDR(3),
			      SPI_MEM_OP_NO_DATA,
			      intel_spi_erase,
			      HSFSTS_CTL_FCYCLE_ERASE_64K),
	INTEL_SPI_MEM_OP_REPL(SPI_MEM_OP_CMD(SPINOR_OP_SE, 1),
			      INTEL_SPI_OP_ADDR(4),
			      SPI_MEM_OP_NO_DATA,
			      intel_spi_erase,
			      HSFSTS_CTL_FCYCLE_ERASE_64K),
	INTEL_SPI_MEM_OP_REPL(SPI_MEM_OP_CMD(SPINOR_OP_SE_4B, 1),
			      INTEL_SPI_OP_ADDR(4),
			      SPI_MEM_OP_NO_DATA,
			      intel_spi_erase,
			      HSFSTS_CTL_FCYCLE_ERASE_64K),
	{ },
};

static int intel_spi_init(struct intel_spi *ispi)
{
	u32 opmenu0, opmenu1, lvscc, uvscc, val;
	bool erase_64k = false;

	ispi->swseq_enabled = is_swseq_enabled();

	switch (ispi->info->type) {
	case INTEL_SPI_BYT:
		ispi->sregs = ispi->base + BYT_SSFSTS_CTL;
		ispi->pregs = ispi->base + BYT_PR;
		ispi->nregions = BYT_FREG_NUM;
		ispi->pr_num = BYT_PR_NUM;
		ispi->swseq_reg = true;
		break;

	case INTEL_SPI_LPT:
		ispi->sregs = ispi->base + LPT_SSFSTS_CTL;
		ispi->pregs = ispi->base + LPT_PR;
		ispi->nregions = LPT_FREG_NUM;
		ispi->pr_num = LPT_PR_NUM;
		ispi->swseq_reg = true;
		break;

	case INTEL_SPI_BXT:
		ispi->sregs = ispi->base + BXT_SSFSTS_CTL;
		ispi->pregs = ispi->base + BXT_PR;
		ispi->nregions = BXT_FREG_NUM;
		ispi->pr_num = BXT_PR_NUM;
		erase_64k = true;
		break;

	case INTEL_SPI_CNL:
		ispi->sregs = NULL;
		ispi->pregs = ispi->base + CNL_PR;
		ispi->nregions = CNL_FREG_NUM;
		ispi->pr_num = CNL_PR_NUM;
		erase_64k = true;
		break;

	default:
		return -EINVAL;
	}

	/* Try to disable write protection if user asked to do so */
	if (writeable && !intel_spi_set_writeable(ispi)) {
		dev_warn(ispi->dev, "can't disable chip write protection\n");
		writeable = false;
	}

	/* Disable #SMI generation from HW sequencer */
	val = readl(ispi->base + HSFSTS_CTL);
	val &= ~HSFSTS_CTL_FSMIE;
	writel(val, ispi->base + HSFSTS_CTL);

	/*
	 * Determine whether erase operation should use HW or SW sequencer.
	 *
	 * The HW sequencer has a predefined list of opcodes, with only the
	 * erase opcode being programmable in LVSCC and UVSCC registers.
	 * If these registers don't contain a valid erase opcode, erase
	 * cannot be done using HW sequencer.
	 */
	lvscc = readl(ispi->base + LVSCC);
	uvscc = readl(ispi->base + UVSCC);
	if (!(lvscc & ERASE_OPCODE_MASK) || !(uvscc & ERASE_OPCODE_MASK))
		ispi->swseq_erase = true;
	/* SPI controller on Intel BXT supports 64K erase opcode */
	if (ispi->info->type == INTEL_SPI_BXT && !ispi->swseq_erase)
		if (!(lvscc & ERASE_64K_OPCODE_MASK) ||
		    !(uvscc & ERASE_64K_OPCODE_MASK))
			erase_64k = false;

	if (!ispi->sregs && (ispi->swseq_reg || ispi->swseq_erase)) {
		dev_err(ispi->dev, "software sequencer not supported, but required\n");
		return -EINVAL;
	}


	/*
	 * Some controllers can only do basic operations using hardware
	 * sequencer. All other operations are supposed to be carried out
	 * using software sequencer.
	 */
	if (ispi->swseq_reg && ispi->swseq_enabled) {
		/* Disable #SMI generation from SW sequencer */
        disable_smi_generation(ispi);
	}

	/* Check controller's lock status */
	val = readl(ispi->base + HSFSTS_CTL);
	ispi->locked = !!(val & HSFSTS_CTL_FLOCKDN);

	if (ispi->locked && ispi->sregs && ispi->swseq_enabled) {
		/*
		 * BIOS programs allowed opcodes and then locks down the
		 * register. So read back what opcodes it decided to support.
		 * That's the set we are going to support as well.
		 */
        populate_opmenus(ispi, &opmenu0, &opmenu1);
	}

	if (erase_64k) {
		dev_dbg(ispi->dev, "Using erase_64k memory operations");
		ispi->mem_ops = erase_64k_mem_ops;
	} else {
		dev_dbg(ispi->dev, "Using generic memory operations");
		ispi->mem_ops = generic_mem_ops;
	}

	intel_spi_dump_regs(ispi);
	return 0;
}

static bool intel_spi_is_protected(const struct intel_spi *ispi,
				   unsigned int base, unsigned int limit)
{
	int i;

	for (i = 0; i < ispi->pr_num; i++) {
		u32 pr_base, pr_limit, pr_value;

		pr_value = readl(ispi->pregs + PR(i));
		if (!(pr_value & (PR_WPE | PR_RPE)))
			continue;

		pr_limit = (pr_value & PR_LIMIT_MASK) >> PR_LIMIT_SHIFT;
		pr_base = pr_value & PR_BASE_MASK;

		if (pr_base >= base && pr_limit <= limit)
			return true;
	}

	return false;
}

/*
 * There will be a single partition holding all enabled flash regions. We
 * call this "BIOS".
 */
static void intel_spi_fill_partition(struct intel_spi *ispi,
				     struct mtd_partition *part)
{
	u64 end;
	int i;

	memset(part, 0, sizeof(*part));

	/* Start from the mandatory descriptor region */
	part->size = 4096;
	part->name = "BIOS";

	/*
	 * Now try to find where this partition ends based on the flash
	 * region registers.
	 */
	for (i = 1; i < ispi->nregions; i++) {
		u32 region, base, limit;

		region = readl(ispi->base + FREG(i));
		base = region & FREG_BASE_MASK;
		limit = (region & FREG_LIMIT_MASK) >> FREG_LIMIT_SHIFT;

		if (base >= limit || limit == 0)
			continue;

		/*
		 * If any of the regions have protection bits set, make the
		 * whole partition read-only to be on the safe side.
		 *
		 * Also if the user did not ask the chip to be writeable
		 * mask the bit too.
		 */
		if (!writeable || intel_spi_is_protected(ispi, base, limit))
			part->mask_flags |= MTD_WRITEABLE;

		end = (limit << 12) + 4096;
		if (end > part->size)
			part->size = end;
	}
}

static int intel_spi_read_desc(struct intel_spi *ispi)
{
	struct spi_mem_op op =
		SPI_MEM_OP(SPI_MEM_OP_CMD(SPINOR_OP_READ, 0),
			   SPI_MEM_OP_ADDR(3, 0, 0),
			   SPI_MEM_OP_NO_DUMMY,
			   SPI_MEM_OP_DATA_IN(0, NULL, 0));
	u32 buf[2], nc, fcba, flcomp;
	ssize_t ret;

	op.addr.val = 0x10;
	op.data.buf.in = buf;
	op.data.nbytes = sizeof(buf);

	ret = intel_spi_read(ispi, NULL, NULL, &op);
	if (ret) {
		dev_warn(ispi->dev, "failed to read descriptor\n");
		return ret;
	}

	dev_dbg(ispi->dev, "FLVALSIG=0x%08x\n", buf[0]);
	dev_dbg(ispi->dev, "FLMAP0=0x%08x\n", buf[1]);

	if (buf[0] != FLVALSIG_MAGIC) {
		dev_warn(ispi->dev, "descriptor signature not valid\n");
		return -ENODEV;
	}

	fcba = (buf[1] & FLMAP0_FCBA_MASK) << 4;
	dev_dbg(ispi->dev, "FCBA=%#x\n", fcba);

	op.addr.val = fcba;
	op.data.buf.in = &flcomp;
	op.data.nbytes = sizeof(flcomp);

	ret = intel_spi_read(ispi, NULL, NULL, &op);
	if (ret) {
		dev_warn(ispi->dev, "failed to read FLCOMP\n");
		return -ENODEV;
	}

	dev_dbg(ispi->dev, "FLCOMP=0x%08x\n", flcomp);

	switch (flcomp & FLCOMP_C0DEN_MASK) {
	case FLCOMP_C0DEN_512K:
		ispi->chip0_size = SZ_512K;
		break;
	case FLCOMP_C0DEN_1M:
		ispi->chip0_size = SZ_1M;
		break;
	case FLCOMP_C0DEN_2M:
		ispi->chip0_size = SZ_2M;
		break;
	case FLCOMP_C0DEN_4M:
		ispi->chip0_size = SZ_4M;
		break;
	case FLCOMP_C0DEN_8M:
		ispi->chip0_size = SZ_8M;
		break;
	case FLCOMP_C0DEN_16M:
		ispi->chip0_size = SZ_16M;
		break;
	case FLCOMP_C0DEN_32M:
		ispi->chip0_size = SZ_32M;
		break;
	case FLCOMP_C0DEN_64M:
		ispi->chip0_size = SZ_64M;
		break;
	default:
		return -EINVAL;
	}

	dev_dbg(ispi->dev, "chip0 size %zd KB\n", ispi->chip0_size / SZ_1K);

	nc = (buf[1] & FLMAP0_NC_MASK) >> FLMAP0_NC_SHIFT;
	if (!nc)
		ispi->master->num_chipselect = 1;
	else if (nc == 1)
		ispi->master->num_chipselect = 2;
	else
		return -EINVAL;

	dev_dbg(ispi->dev, "%u flash components found\n",
		ispi->master->num_chipselect);
	return 0;
}

static int intel_spi_populate_chip(struct intel_spi *ispi)
{
	struct flash_platform_data *pdata;
	struct spi_board_info chip;
	int ret;

	pdata = devm_kzalloc(ispi->dev, sizeof(*pdata), GFP_KERNEL);
	if (!pdata)
		return -ENOMEM;

	pdata->nr_parts = 1;
	pdata->parts = devm_kcalloc(ispi->dev, pdata->nr_parts,
				    sizeof(*pdata->parts), GFP_KERNEL);
	if (!pdata->parts)
		return -ENOMEM;

	intel_spi_fill_partition(ispi, pdata->parts);

	memset(&chip, 0, sizeof(chip));
	snprintf(chip.modalias, 8, "spi-nor");
	chip.platform_data = pdata;

	if (!spi_new_device(ispi->master, &chip))
		return -ENODEV;

	/* Add the second chip if present */
	if (ispi->master->num_chipselect < 2)
		return 0;

	ret = intel_spi_read_desc(ispi);
	if (ret)
		return ret;

	chip.platform_data = NULL;
	chip.chip_select = 1;

	if (!spi_new_device(ispi->master, &chip))
		return -ENODEV;
	return 0;
}

/**
 * intel_spi_probe() - Probe the Intel SPI flash controller
 * @dev: Pointer to the parent device
 * @mem: MMIO resource
 * @info: Platform specific information
 *
 * Probes Intel SPI flash controller and creates the flash chip device.
 * Returns %0 on success and negative errno in case of failure.
 */
int intel_spi_probe(struct device *dev, struct resource *mem,
		    const struct intel_spi_boardinfo *info)
{
	struct spi_controller *master;
	struct intel_spi *ispi;
	int ret;

	master = devm_spi_alloc_master(dev, sizeof(*ispi));
	if (!master)
		return -ENOMEM;

	master->mem_ops = &intel_spi_mem_ops;

	ispi = spi_master_get_devdata(master);

	ispi->base = devm_ioremap_resource(dev, mem);
	if (IS_ERR(ispi->base))
		return PTR_ERR(ispi->base);

	ispi->dev = dev;
	ispi->master = master;
	ispi->info = info;

	ret = intel_spi_init(ispi);
	if (ret)
		return ret;

	ret = devm_spi_register_master(dev, master);
	if (ret)
		return ret;

	return intel_spi_populate_chip(ispi);
}
EXPORT_SYMBOL_GPL(intel_spi_probe);

MODULE_DESCRIPTION("Intel PCH/PCU SPI flash core driver");
MODULE_AUTHOR("Mika Westerberg <mika.westerberg@linux.intel.com>");
MODULE_LICENSE("GPL v2");
