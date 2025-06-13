Name:       ecapture
Version:    v1.1.0
Release:    2025%{?dist}
Summary:    Capture SSL/TLS plaintext content without CA certificates using eBPF
License:    Apache-2.0
URL:        https://ecapture.cc
Source0:    %{name}-%{version}.tar.gz

%global _missing_build_ids_terminate_build 0
%define debug_package %{nil}


%description
eCapture is a powerful network traffic capture and decryption tool based on eBPF technology, focusing on TLS/SSL protocol transparency and analysis. This tool supports multiple protocols and architectures, providing efficient and flexible capture and decryption capabilities.

Key features include:
- Multi-Protocol Support: Compatible with TLS, gnutls, nss, openssl, and other encryption protocols across different versions of SSL/TLS implementations
- Smart Packet Capture: Efficient network data capture and protocol parsing based on eBPF technology, supporting IPv4/IPv6 dual-stack and 4-tuple filtering
- Master Key Capture: Supports TLS 1.0/1.1/1.2 and 1.3 protocol master key capture, integrates with Wireshark for decryption to view encrypted traffic in plain text
- Modular Architecture: Easy extension and flexible configuration of different protocol modules
- Cross-Platform Support: Compatible with Linux, Android, and other platforms, supporting ARM64 and x86 architectures

Technical advantages:
- Automatic detection of SSL/TLS library versions, intelligent identification of CO-RE and non-CO-RE modes
- Support for custom filters, log files, decryption modes, and multiple output formats
- High-efficiency data processing based on eBPF, supporting large-scale concurrent captures and long-term packet capturing
- Wireshark plugin support for easy data analysis and visualization

Application scenarios: Network debugging, security analysis, protocol research, monitoring and auditing.

For more information, visit: https://ecapture.cc or https://github.com/gojue/ecapture

%prep
%setup -c

%build
make

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/local/bin/
install -m 755 bin/ecapture %{buildroot}/usr/local/bin/ecapture
eu-strip %{buildroot}/usr/local/bin/ecapture

%post
echo "eCapture has been installed in the /usr/local/bin directory."
echo "Please ensure that /usr/local/bin is in your \$PATH, or use /usr/local/bin/ecapture directly."

%files
/usr/local/bin/ecapture

%changelog
* Tue Mar 25 2025 CFC4N <cfc4ncs@gmail.com> - 1.0.0
- Initial stable release
- Added support for multiple encryption protocols including TLS, gnutls, nss, and openssl
- Implemented smart packet capture based on eBPF technology
- Added support for TLS 1.2 and 1.3 protocol master key capture
- Completed modular architecture design for easy extension
- Added cross-platform support for Linux, Android, and other platforms
- Ensured compatibility with ARM64 and x86 architectures
- Added Wireshark plugin support
- Implemented automatic detection of SSL/TLS library versions
- Added support for custom filters, log files, and multiple output formats