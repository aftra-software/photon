# Photon

Photon is a (Work In Progress) blazing-fast and highly efficient security scanning tool written in Rust. It is designed to be mostly compatible with [Nuclei](https://github.com/projectdiscovery/nuclei) templates while optimizing for performance and minimizing redundant requests.


## Features 🚀

- **Nuclei Template Compatibility**: Supports most Nuclei templates, enabling easy adoption and integration with existing workflows.
  - Most templates are supported, though Workflows and exotic template features currently aren't.
- **Unparalleled Speed**: Built with Rust for high performance and efficiency.
- **Request Optimization**: Sends minimal requests while achieving accurate results through intelligent request caching.
- **Lightweight and Scalable**: Designed for both individual researchers and large-scale scanning operations.
- **Photon Lib**: Integrate against Photon directly using the `photon` library.
- **Photon DSL**: Standalone Nuclei-compatible DSL written from scratch for simplicity and stability. 


## Why Photon? 🔍

Photon stands out with its **focus on efficiency**:
- **Caching Responses**: Reuses responses intelligently to reduce network load and scan time.
- **Resource Efficiency**: Optimized for low CPU and memory consumption, making it suitable for constrained environments.
- **Careful Scanning**: Photon carefully scans, making sure not to overload the target by only having one concurrent request at any given time.
  - Will support multiple concurrent requests in the future.


## Installation 🛠️

Installing from source or via Cargo are currently the only available options to install Photon.

Ensure you have the [Rust](https://github.com/rust-lang/rust) toolchain installed.
### Using Cargo
```bash
cargo install --git https://github.com/aftra-software/photon.git
```

### From Source
```bash
git clone https://github.com/aftra-software/photon.git
cd photon
cargo build --release
sudo mv target/release/photon /usr/local/bin/
```


## Usage 📖

### Basic Scan
Run Photon with a Nuclei template:
```bash
photon -t template.yaml -u https://example.com
```

### Template Directory
Use a directory of templates:
```bash
photon -t /path/to/templates/ -u https://example.com
```

For a full list of options:
```bash
photon --help
```


## Example Workflow 🧑‍💻

1. Fetch and update the latest Nuclei templates:
   ```bash
   nuclei -update-templates
   ```
   or
   ```bash
   git clone https://github.com/projectdiscovery/nuclei-templates.git
   ```
2. Use Photon to scan your target with the updated templates:
   ```bash
   photon -t ~/.nuclei-templates/ -u https://example.com
   ```


## Benchmarks 🔥

Coming Soon...


## Contributing 🤝

We welcome contributions to Photon! To get started:
1. Fork the repository.
2. Create a feature branch:
   ```bash
   git checkout -b feature-name
   ```
3. Commit and push your changes.
4. Open a Pull Request.


## License 📜

Photon is licensed under the [MIT License](LICENSE).


## Acknowledgments ❤️

Photon is inspired by and built upon the ideas of [ProjectDiscovery's Nuclei](https://github.com/projectdiscovery/nuclei). Special thanks to ProjectDiscovery for their amazing work on Nuclei.


## Contact Us 📧

For questions or support, feel free to [open an issue](https://github.com/aftra-software/photon/issues).