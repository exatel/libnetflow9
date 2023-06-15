# external libraries sources directory

The external libraries are not used by default, instead it's expected they
are installed system-wide. System libraries have advantages, e.g. you can
rely on them in an airgapped environment. On the other hand, they are missing
from some distributions.

In order to activate the external libraries set to ON the correspoding cmake
option[-s]:

* `NF9_USE_OWN_LIBTINS`
* `NF9_USE_OWN_GTEST`

## libtins
https://github.com/mfontanini/libtins.git

Incorporated as a submodule as described here:

https://git-scm.com/book/en/v2/Git-Tools-Submodules

## googtest
pulled directly from github release as recommended here:

https://github.com/google/googletest/blob/main/googletest/README.md

Overthere see the description below the last bullet point "Use CMake
to download GoogleTest as part of the build's configure step. This approach
doesn't have the limitations of the other methods."
