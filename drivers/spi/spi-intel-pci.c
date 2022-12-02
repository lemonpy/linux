// SPDX-License-Identifier: GPL-2.0-only
/*
 * Intel PCH/PCU SPI flash PCI driver.
 *
 * Copyright (C) 2016 - 2022, Intel Corporation
 * Author: Mika Westerberg <mika.westerberg@linux.intel.com>
 */

#include <linux/module.h>
#include <linux/pci.h>

#include "spi-intel.h"

#define BCR		0xdc
#define BCR_WPD		BIT(0)

static bool intel_spi_pci_set_writeable(void __iomem *base, void *data)
{
	struct pci_dev *pdev = data;
	u32 bcr;

	/* Try to make the chip read/write */
	pci_read_config_dword(pdev, BCR, &bcr);
	if (!(bcr & BCR_WPD)) {
		bcr |= BCR_WPD;
		pci_write_config_dword(pdev, BCR, bcr);
		pci_read_config_dword(pdev, BCR, &bcr);
	}

	return bcr & BCR_WPD;
}

static const struct intel_spi_boardinfo bxt_info = {
	.type = INTEL_SPI_BXT,
	.set_writeable = intel_spi_pci_set_writeable,
};

static const struct intel_spi_boardinfo cnl_info = {
	.type = INTEL_SPI_CNL,
	.set_writeable = intel_spi_pci_set_writeable,
};

static int intel_spi_pci_probe(struct pci_dev *pdev,
			       const struct pci_device_id *id)
{
	struct intel_spi_boardinfo *info;
	int ret;

	ret = pcim_enable_device(pdev);
	if (ret)
		return ret;

	info = devm_kmemdup(&pdev->dev, (void *)id->driver_data, sizeof(*info),
			    GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	info->data = pdev;
	return intel_spi_probe(&pdev->dev, &pdev->resource[0], info);
}

static const struct pci_device_id intel_spi_pci_ids[] = {
	// Lewisburg C620 Series Verified
	// Chipset Production SKUs
	{ PCI_VDEVICE(INTEL, 0xa1a4), (unsigned long)&bxt_info },
	// Chipset Super SKUs
	{ PCI_VDEVICE(INTEL, 0xa224), (unsigned long)&bxt_info },

    // Emmitsburg same controller as Lewisburg
    // commit: fef95b7211deb80c19ebfcdd5208ec7b80b40cbf
	{ PCI_VDEVICE(INTEL, 0x1bca), (unsigned long)&bxt_info },

    // Tiger lake (500 Series)
    // Tiger Lake-H
	{ PCI_VDEVICE(INTEL, 0x43a4), (unsigned long)&cnl_info }, /* verified https://www.intel.com/content/www/us/en/content-details/636174/intel-500-series-chipset-family-platform-controller-hub-pch-datasheet-volume-2-of-2.html */

    // commit: a0eec15673222ef52655fc6a5da0008c501aebdc
    // Tiger lake (500 Series) on package
    // Inconsistency with datasheet
    // https://www.intel.com/content/www/us/en/content-details/631120/intel-500-series-chipset-family-on-package-platform-controller-hub-datasheet-volume-2-of-2.html
    // Reason: it has 6 FREG_NUM and 6 PR_NUM (Counting Global as any other case)
    // Non bxt nor cnl compatible
	{ PCI_VDEVICE(INTEL, 0xa0a4), (unsigned long)&bxt_info },

    // Cannon Point (300 Series and c240 Series)
    // Inconsistency with datasheet
    // 300 Series PCH Datasheet Vol. 2 (broken link in intel.com)
    // Reason: it has 6 FREG_NUM and 6 PR_NUM (Counting Global as any other case)
    // Non bxt nor cnl compatible
	{ PCI_VDEVICE(INTEL, 0xa324), (unsigned long)&cnl_info },

    // Found in kernel
    // Alder Lake-S
    // commit: 3a9dcb2586e1b7f4c44c1f4f51d16ab43252ddb2
    // Inconsistency with datasheet
    // Intel® 600 Series Chipset Family Platform Controller Hub (PCH) Datasheet, Volume 2 of 2
    // Reason: it has 6 FREG_NUM and 6 PR_NUM (Counting Global as any other case)
    // Should be counting global pr????
	{ PCI_VDEVICE(INTEL, 0x7aa4), (unsigned long)&cnl_info },
    // Alder Lake-P
    // commit: d5802468c358cd421c09355467be36a41ea5b5d6
    // No datasheet found for specific -P (Performance) model
    // Same as -S model?
	{ PCI_VDEVICE(INTEL, 0x51a4), (unsigned long)&cnl_info },
    // Alder Lake-M
    // No datasheet found for specific -M model
    // commit: 854955ae96dbd436ba4719dd1cedb7c1c40bd303
	{ PCI_VDEVICE(INTEL, 0x54a4), (unsigned long)&cnl_info },
    // Raptor Lake-S
    // No datasheet found, using 600 Series chipset
    // commit: 299d8b74519d04042f8803d0604e08a1a7e31e5e
	{ PCI_VDEVICE(INTEL, 0x7a24), (unsigned long)&cnl_info },
    // Meteor Lake-P
    // No info Dec,2
	{ PCI_VDEVICE(INTEL, 0x7e23), (unsigned long)&cnl_info },

    // Comet Lake 400 Series Chipset Family On-Package PCH
    // Inconsistency with datasheet same as prev line
    // Reason: it has 6 FREG_NUM and 6 PR_NUM (Counting Global as any other case)
    // Should be counting global pr???? If not, this should be cnl compatible
	{ PCI_VDEVICE(INTEL, 0x02a4), (unsigned long)&bxt_info },

    // Comet Lake ID: 620854-002
    // Inconsistency with datasheet
    // Intel® 400 Series Chipset Family Platform Controller Hub Vol 2
    // Reason: it has 6 FREG_NUM and 6 PR_NUM (Counting Global as any other case)
    // Should be counting global pr???? If not, this should be cnl compatible
	{ PCI_VDEVICE(INTEL, 0x06a4), (unsigned long)&bxt_info },
    // end Comet Lake

    // Missing
	{ PCI_VDEVICE(INTEL, 0x18e0), (unsigned long)&bxt_info },
	{ PCI_VDEVICE(INTEL, 0x4b24), (unsigned long)&bxt_info },

    // Atom Processor C3000 Series
    // No data found
	{ PCI_VDEVICE(INTEL, 0x19e0), (unsigned long)&bxt_info },

    // Ice Lake-LP 10th gen Intel 495 Chipset Family On-Package
    // Inconsistency with datasheet
    // Intel 495 Chipset Family On-Package
    // Reason: it has 6 FREG_NUM and 6 PR_NUM (Counting Global as any other case)
    // Should be counting global pr???? If not, this should be cnl compatible
	{ PCI_VDEVICE(INTEL, 0x34a4), (unsigned long)&bxt_info },
    // Ice Lake
    // No data found
	{ PCI_VDEVICE(INTEL, 0x38a4), (unsigned long)&bxt_info },
    // end Ice Lake-LP

    // Jasper Lake
    // No data found
	{ PCI_VDEVICE(INTEL, 0x4da4), (unsigned long)&bxt_info },
    // end Jasper Lake

    // Intel B460 and H410 Chipset
    // Inconsistency with datasheet
    // Intel B460 and H410 Chipset vol 2
    // Reason: it has 6 FREG_NUM and 6 PR_NUM (Counting Global as any other case)
    // Should be counting global pr????
	{ PCI_VDEVICE(INTEL, 0xa3a4), (unsigned long)&bxt_info },

    /* 9da4  Cannon Point-LP SPI Controller */
    /* a2a4  200 Series/Z370 Chipset Family SPI Controller */
    /* a1a4  C620 Series Chipset Family SPI Controller */
    /* a324  Cannon Lake PCH SPI Controller */
    /* 9d24  Intel B460 and H410 Chipset Platform Controller Hub (PCH) */

    /* How to handle stepping on spi devices? */
	{ },
};
MODULE_DEVICE_TABLE(pci, intel_spi_pci_ids);

static struct pci_driver intel_spi_pci_driver = {
	.name = "intel-spi",
	.id_table = intel_spi_pci_ids,
	.probe = intel_spi_pci_probe,
};

module_pci_driver(intel_spi_pci_driver);

MODULE_DESCRIPTION("Intel PCH/PCU SPI flash PCI driver");
MODULE_AUTHOR("Mika Westerberg <mika.westerberg@linux.intel.com>");
MODULE_LICENSE("GPL v2");
