// SPDX-License-Identifier: GPL-2.0-only
/*
 * Intel PCH/PCU SPI flash driver.
 *
 * Copyright (C) 2016 - 2022, Intel Corporation
 * Author: Mika Westerberg <mika.westerberg@linux.intel.com>
 */

#ifndef SPI_INTEL_SWSEQ_H
#define SPI_INTEL_SWSEQ_H

#include <linux/types.h>

int intel_spi_sw_cycle(struct intel_spi *ispi, u8 opcode, size_t len,
		       int optype);
inline bool is_swseq_enabled(void);
int handle_swseq_wren(struct intel_spi *ispi);
bool mem_op_supported_on_spi_locked(const struct intel_spi *ispi,
				    const struct spi_mem_op *op);
void disable_smi_generation(const struct intel_spi *ispi);
void populate_opmenus(struct intel_spi *ispi, u32 *opmenu0, u32 *opmenu1);

#endif /* SPI_INTEL_SWSEQ_H */

