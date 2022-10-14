// SPDX-License-Identifier: GPL-2.0-only
/*
 * Intel PCH/PCU SPI flash driver.
 *
 * Copyright (C) 2016 - 2022, Intel Corporation
 * Author: Mika Westerberg <mika.westerberg@linux.intel.com>
 */

#ifndef SPI_INTEL_COMMON_H
#define SPI_INTEL_COMMON_H

#include <linux/spi/spi-mem.h>
#include <linux/mtd/spi-nor.h>

/* Offsets are from @ispi->base */
#define BFPREG				0x00

#define HSFSTS_CTL			0x04
#define HSFSTS_CTL_FSMIE		BIT(31)
#define HSFSTS_CTL_FDBC_SHIFT		24
#define HSFSTS_CTL_FDBC_MASK		(0x3f << HSFSTS_CTL_FDBC_SHIFT)

#define HSFSTS_CTL_FCYCLE_SHIFT		17
#define HSFSTS_CTL_FCYCLE_MASK		(0x0f << HSFSTS_CTL_FCYCLE_SHIFT)
/* HW sequencer opcodes */
#define HSFSTS_CTL_FCYCLE_READ		(0x00 << HSFSTS_CTL_FCYCLE_SHIFT)
#define HSFSTS_CTL_FCYCLE_WRITE		(0x02 << HSFSTS_CTL_FCYCLE_SHIFT)
#define HSFSTS_CTL_FCYCLE_ERASE		(0x03 << HSFSTS_CTL_FCYCLE_SHIFT)
#define HSFSTS_CTL_FCYCLE_ERASE_64K	(0x04 << HSFSTS_CTL_FCYCLE_SHIFT)
#define HSFSTS_CTL_FCYCLE_RDID		(0x06 << HSFSTS_CTL_FCYCLE_SHIFT)
#define HSFSTS_CTL_FCYCLE_WRSR		(0x07 << HSFSTS_CTL_FCYCLE_SHIFT)
#define HSFSTS_CTL_FCYCLE_RDSR		(0x08 << HSFSTS_CTL_FCYCLE_SHIFT)

#define HSFSTS_CTL_FGO			BIT(16)
#define HSFSTS_CTL_FLOCKDN		BIT(15)
#define HSFSTS_CTL_FDV			BIT(14)
#define HSFSTS_CTL_SCIP			BIT(5)
#define HSFSTS_CTL_AEL			BIT(2)
#define HSFSTS_CTL_FCERR		BIT(1)
#define HSFSTS_CTL_FDONE		BIT(0)

#define FADDR				0x08
#define DLOCK				0x0c
#define FDATA(n)			(0x10 + ((n) * 4))

#define FRACC				0x50

#define FREG(n)				(0x54 + ((n) * 4))
#define FREG_BASE_MASK			0x3fff
#define FREG_LIMIT_SHIFT		16
#define FREG_LIMIT_MASK			(0x03fff << FREG_LIMIT_SHIFT)

/* Offset is from @ispi->pregs */
#define PR(n)				((n) * 4)
#define PR_WPE				BIT(31)
#define PR_LIMIT_SHIFT			16
#define PR_LIMIT_MASK			(0x3fff << PR_LIMIT_SHIFT)
#define PR_RPE				BIT(15)
#define PR_BASE_MASK			0x3fff

/* Offsets are from @ispi->sregs */
#define SSFSTS_CTL			0x00
#define SSFSTS_CTL_FSMIE		BIT(23)
#define SSFSTS_CTL_DS			BIT(22)
#define SSFSTS_CTL_DBC_SHIFT		16
#define SSFSTS_CTL_SPOP			BIT(11)
#define SSFSTS_CTL_ACS			BIT(10)
#define SSFSTS_CTL_SCGO			BIT(9)
#define SSFSTS_CTL_COP_SHIFT		12
#define SSFSTS_CTL_FRS			BIT(7)
#define SSFSTS_CTL_DOFRS		BIT(6)
#define SSFSTS_CTL_AEL			BIT(4)
#define SSFSTS_CTL_FCERR		BIT(3)
#define SSFSTS_CTL_FDONE		BIT(2)
#define SSFSTS_CTL_SCIP			BIT(0)

#define PREOP_OPTYPE			0x04
#define OPMENU0				0x08
#define OPMENU1				0x0c

#define OPTYPE_READ_NO_ADDR		0
#define OPTYPE_WRITE_NO_ADDR		1
#define OPTYPE_READ_WITH_ADDR		2
#define OPTYPE_WRITE_WITH_ADDR		3

/* CPU specifics */
#define BYT_PR				0x74
#define BYT_SSFSTS_CTL			0x90
#define BYT_FREG_NUM			5
#define BYT_PR_NUM			5

#define LPT_PR				0x74
#define LPT_SSFSTS_CTL			0x90
#define LPT_FREG_NUM			5
#define LPT_PR_NUM			5

#define BXT_PR				0x84
#define BXT_SSFSTS_CTL			0xa0
#define BXT_FREG_NUM			12
#define BXT_PR_NUM			6

#define CNL_PR				0x84
#define CNL_FREG_NUM			6
#define CNL_PR_NUM			5

#define LVSCC				0xc4
#define UVSCC				0xc8
#define ERASE_OPCODE_SHIFT		8
#define ERASE_OPCODE_MASK		(0xff << ERASE_OPCODE_SHIFT)
#define ERASE_64K_OPCODE_SHIFT		16
#define ERASE_64K_OPCODE_MASK		(0xff << ERASE_OPCODE_SHIFT)

/* Flash descriptor fields */
#define FLVALSIG_MAGIC			0x0ff0a55a
#define FLMAP0_NC_MASK			GENMASK(9, 8)
#define FLMAP0_NC_SHIFT			8
#define FLMAP0_FCBA_MASK		GENMASK(7, 0)

#define FLCOMP_C0DEN_MASK		GENMASK(3, 0)
#define FLCOMP_C0DEN_512K		0x00
#define FLCOMP_C0DEN_1M			0x01
#define FLCOMP_C0DEN_2M			0x02
#define FLCOMP_C0DEN_4M			0x03
#define FLCOMP_C0DEN_8M			0x04
#define FLCOMP_C0DEN_16M		0x05
#define FLCOMP_C0DEN_32M		0x06
#define FLCOMP_C0DEN_64M		0x07

#define INTEL_SPI_TIMEOUT		5000 /* ms */
#define INTEL_SPI_FIFO_SZ		64

/**
 * struct intel_spi - Driver private data
 * @dev: Device pointer
 * @info: Pointer to board specific info
 * @base: Beginning of MMIO space
 * @pregs: Start of protection registers
 * @sregs: Start of software sequencer registers
 * @master: Pointer to the SPI controller structure
 * @nregions: Maximum number of regions
 * @pr_num: Maximum number of protected range registers
 * @chip0_size: Size of the first flash chip in bytes
 * @locked: Is SPI setting locked
 * @swseq_reg: Use SW sequencer in register reads/writes
 * @swseq_erase: Use SW sequencer in erase operation
 * @swseq_enabled: SW sequencer enabled to use
 * @atomic_preopcode: Holds preopcode when atomic sequence is requested
 * @opcodes: Opcodes which are supported. This are programmed by BIOS
 *           before it locks down the controller.
 * @mem_ops: Pointer to SPI MEM ops supported by the controller
 */
struct intel_spi {
	struct device *dev;
	const struct intel_spi_boardinfo *info;
	void __iomem *base;
	void __iomem *pregs;
	void __iomem *sregs;
	struct spi_controller *master;
	size_t nregions;
	size_t pr_num;
	size_t chip0_size;
	bool locked;
	bool swseq_reg;
	bool swseq_erase;
    bool swseq_enabled;
	u8 atomic_preopcode;
	u8 opcodes[8];
	const struct intel_spi_mem_op *mem_ops;
};

struct intel_spi_mem_op {
	struct spi_mem_op mem_op;
	u32 replacement_op;
	int (*exec_op)(struct intel_spi *ispi,
		       const struct spi_mem *mem,
		       const struct intel_spi_mem_op *iop,
		       const struct spi_mem_op *op);
};

#endif /* SPI_INTEL_COMMON_H */
