Name:           skiff
Version:        0.1.0
Release:        0
Summary:        OCI image layer analysis tool
License:        Apache-2.0
URL:            https://github.com/dcermak/skiff
Source0:        skiff-%{version}.tar.gz
BuildRequires:  golang-packaging
BuildRequires:  golang(API) >= 1.23
BuildRequires:  libbtrfs-devel
BuildRequires:  libgpgme-devel

%description
skiff is a tool for inspecting OCI container image layers.
It provides two commands:
  layers - show uncompressed size of each layer
  top    - show the largest files across layers

%prep
%autosetup -p1

%build
go build \
    -mod=vendor \
    -buildmode=pie \
    -o bin/skiff \
    ./cmd/skiff/

%install
install -D -m0755 bin/skiff %{buildroot}%{_bindir}/skiff

%files
%license LICENSE
%{_bindir}/skiff
