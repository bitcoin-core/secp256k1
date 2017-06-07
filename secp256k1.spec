%define		gitdate	20015.12.20

Name:		secp256k1
Version:	0.0.%{gitdate}
Release:	1%{?dist}
Summary:	Optimized C library for EC operations on curve secp256k1

Group:		System Environment/Libraries
License:	MIT
URL:		https://github.com/bitcoin/secp256k1
Source0:	%{name}-master.zip

#BuildRequires:	
#Requires:	

%description
Optimized C library for EC operations on curve secp256k1.

This library is a work in progress and is being used to research best practices.
Use at your own risk.

%package devel
Requires:	%{name} = %{version}-%{release}
Group:		Development/Libraries
Summary:	Development files for %{name}

%description devel
This package contains the static library and development header files for the
%{name} library.


%prep
%setup -q -n %{name}-master


%build
#
cp Makefile.am Makefile.am.orig
sed -e s?"(libdir)/pkgconfig"?"(datadir)/pkgconfig"? < Makefile.am.orig > Makefile.am
./autogen.sh
%configure --enable-module-recovery
make %{?_smp_mflags}


%install
make install DESTDIR=%{buildroot}
rm -f %{buildroot}%{_libdir}/*.la

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%doc COPYING README.md TODO
%{_libdir}/*.so.*

%files devel
%defattr(-,root,root,-)
%{_includedir}/*.h
%{_libdir}/*.a
%{_libdir}/*.so
%{_datadir}/pkgconfig/*.pc



%changelog
* Sun Dec 20 2015 Alice Wonder <buildmaster@librelamp.com> - 0.0.2015.12.20
- Initial RPM spec file
