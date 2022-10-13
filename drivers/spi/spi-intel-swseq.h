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

int intel_spi_sw_cycle(const struct intel_spi *ispi, const u8 opcode, const size_t len,
		       const int optype);
inline bool is_swseq_enabled(void);
int handle_swseq_wren(const struct intel_spi *ispi);
bool mem_op_supported_on_spi_locked(const struct intel_spi *ispi,
				    const struct spi_mem_op *op);

#endif /* SPI_INTEL_SWSEQ_H */

