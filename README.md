# HavenOverflow's Cr50 Fork
This is a fork of the open source Cr50 firmware available at src/platform/cr50, modified to contain custom software and reverse engineered firmware for other Google Security Chips.

_Note: This fork is intended to be compiled as a component of Smiko! Do not try to build this seperately, instead view the build instructions in [the Smiko Repo](https://github.com/HavenOverflow/Smiko)._

## Building
The following boards are able to be built:
```bash
BRANCH=(MP|PREPVT|TOT) BOARD=cr50 make # Build stock Cr50 loader, firmware, and BootROM for Haven
BRANCH=(MP|PREPVT|TOT) BOARD=smiko make # Build custom Cr50 loader and firmware for Haven
```

Built images will be placed at `build/$(BOARD)/ec.bin`.
