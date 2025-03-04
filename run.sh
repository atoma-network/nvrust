#!/bin/bash

# Get Python library paths
PYTHON_LIB_PATH=$(python3 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))")
PYTHON_FRAMEWORK_PATH=$(python3 -c "import sysconfig; print(sysconfig.get_config_var('PYTHONFRAMEWORKPREFIX'))")
PYTHON_INCLUDE_PATH=$(python3 -c "import sysconfig; print(sysconfig.get_config_var('INCLUDEPY'))")
PYTHON_EXE=$(which python3)

# Set environment variables for PyO3
export PYTHONPATH=$(pwd):$PYTHONPATH
export PYTHON_SYS_EXECUTABLE=$PYTHON_EXE
export DYLD_LIBRARY_PATH=$PYTHON_LIB_PATH:$PYTHON_FRAMEWORK_PATH:$DYLD_LIBRARY_PATH
export LIBRARY_PATH=$PYTHON_LIB_PATH:$PYTHON_FRAMEWORK_PATH:$LIBRARY_PATH

# Clone the nvtrust repository if it doesn't exist
if [ ! -d "external/nvtrust" ]; then
    mkdir -p external
    git clone https://github.com/NVIDIA/nvtrust.git external/nvtrust
fi

# Build and run
cargo build && cargo run "$@" 