# open-mpic-core-python

A Python implementation of the Open MPIC core library which can be adapted to various transports or deployment environments.

## Overview

The `open-mpic-core` library is a "common code" or "core" library for Open MPIC, written in Python. It is designed to be included in Python projects that wrap this code in something that can be invoked to leverage it. 

For example:
- The [aws-lambda-python](https://github.com/open-mpic/aws-lambda-python) GitHub project utilizes this library as part of an AWS Lambda-based MPIC implementation.
- The [open-mpic-containers](https://github.com/open-mpic/open-mpic-containers) GitHub project uses this library to implement the key MPIC components (coordinator, CAA checker, DCV checker) as FastAPI-based Docker images that can be deployed as desired.

## API Specification

The `open-mpic-core` library utilizes object definitions which are based on the Open MPIC API Specification. This codebase is versioned to correspond to the Open MPIC API Specification version on which it is based. MPIC implementations based on this library should therefore be expected to conform to the corresponding Open MPIC API specification.

## Installation

To include the `open-mpic-core` library in your project, add it as a dependency in your `pyproject.toml` file:

```toml
[project]
dependencies = [
  "open-mpic-core"
]
```

Alternatively, you can install it using pip:

```sh
pip install open-mpic-core
```

## Usage

Here is an example of how to use the `open-mpic-core` library in your project:

```python
from open_mpic_core.mpic_caa_checker import MpicCaaChecker
from open_mpic_core.common_domain import CaaCheckRequest, CaaCheckResponse

# Create a CAA check request
caa_request = CaaCheckRequest(
    caa_check_parameters=...  # Fill in the required parameters
)

# Perform the CAA check
checker = MpicCaaChecker()
caa_response = await checker.check_caa(caa_request)

# Process the response
if caa_response.check_passed:
    print("CAA check passed")
else:
    print("CAA check failed")
```

## Contributing

Contributions are welcome! Please see the [contributing guidelines](CONTRIBUTING.md) for more information.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Links

- [Documentation](https://github.com/open-mpic/open-mpic-core-python)
- [Issues](https://github.com/open-mpic/open-mpic-core-python/issues)
- [Source](https://github.com/open-mpic/open-mpic-core-python)

## Authors

- Henry Birge-Lee
- Grace Cimaszewski
- Dmitry Sharkov