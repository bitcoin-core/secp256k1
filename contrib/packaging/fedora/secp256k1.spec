%global git 1e6f1f5a
%global checkout 20180531.git.%{git}

Name:           secp256k1
Version:        0.0.0
Release:        0.%{checkout}%{?dist}
Summary:        Optimized C library for EC operations on curve secp256k1
Group:          Development/Libraries
License:        MIT
URL:            https://github.com/bitcoin-core/secp256k1

Source0:        %{name}-%{version}-%{git}.tar.gz
Provides:       %{name} = %{version}-%{release}

BuildRequires:  coreutils
BuildRequires:  gcc
BuildRequires:  libtool

Requires:       glibc
Requires:       gmp

%description
Optimized C library for EC operations on curve secp256k1.

This library is a work in progress and is being used to research best practices. Use at your own risk.

Features:
- secp256k1 ECDSA signing/verification and key generation.
- Adding/multiplying private/public keys.
- Serialization/parsing of private keys, public keys, signatures.
- Constant time, constant memory access signing and pubkey generation.
- Derandomized DSA (via RFC6979 or with a caller provided function.)
- Very efficient implementation.

%package    devel
Summary:    Development libraries and header files for the Notmuch library
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
Development headers for %{name}.

%prep
%setup -q

%build
./autogen.sh
%configure
make %{?_smp_mflags} CFLAGS="%{optflags} -fPIC"

%install
make install DESTDIR=%{buildroot}

# Enable dynamic library stripping.
find %{buildroot}%{_libdir} -name *.so* -exec chmod 755 {} \;

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%doc COPYING README.md
%{_libdir}/libsecp256k1.so.*
%{_libdir}/libsecp256k1.la

%files devel
%{_includedir}/secp256k1.h
%{_libdir}/pkgconfig/libsecp256k1.pc
%{_libdir}/libsecp256k1.so
%{_libdir}/libsecp256k1.a

%changelog
* Thu Aug 02 2018 Suvayu Ali <fatkasuvayu+linux@gmail.com> - 0.0.0-0.20180531.git.1e6f1f5a
- Unreleased version
