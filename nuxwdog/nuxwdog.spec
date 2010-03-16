# BEGIN COPYRIGHT BLOCK
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# (C) 2009 Red Hat, Inc.
# All rights reserved.
# END COPYRIGHT BLOCK

Name:           nuxwdog
Version:        1.0.0
Release:        2%{?dist}
Summary:        nuxwdog watchdog server
License:        GPLv2 with exceptions
Group:          System Environment/Libraries
URL:            http://www.redhat.com/certificate_system
Vendor:         Red Hat, Inc.
Packager:       %{vendor} <http://bugzilla.redhat.com/bugzilla>

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant
BuildRequires:  bash
BuildRequires:  java-devel >= 1:1.6.0
BuildRequires:  jpackage-utils
BuildRequires:  nspr-devel >= 4.6.99
BuildRequires:  nss-devel >= 3.12.3.99
BuildRequires:  pkgconfig
BuildRequires:  libselinux-devel

Requires:       nss >= 3.12.3.99

Source0:        %{name}-%{version}.tar.gz

%description
The nuxwdog package supplies the nuxwdog watchdog daemon, 
used to start,stop, prompt for passwords and monitor processes.

%package client
Group:        System Environment/Libraries
Summary:      Nuxwdog Watchdog client C/C++ Package

%package client-devel
Group:        Development/Libraries
Summary:      Header files for the Nuxwdog Watchdog
Requires:     %{name}-client = %{version}-%{release}

%package client-java
Group:        System Environment/Libraries
Summary:      Nuxwdog Watchdog client JNI Package
Requires:     java >= 1:1.6.0
Requires:     jpackage-utils
Requires:     %{name}-client = %{version}-%{release}

%package client-perl
Group:        System Environment/Libraries
Summary:      Nuxwdog Watchdog client Perl Package

%description client
The nuxwdog-client package contains C/C++ client code to allow clients
to interact with the nuxwdog server.

%description client-java
The nuxwdog-client-java package contains a JNI interface to the nuxwdog 
client code, so that Java clients can interact with the nuxwdog watchdog 
server.

%description client-perl
The nuxwdog-client-perl package contains a Perl interface to the nuxwdog 
client code, so that Perl clients can interact with the nuxwdog watchdog 
server.

%description client-devel
The nuxwdog-devel package contains the header files needed to build clients
that call WatchdogClient functions, so that clients can interact with the
nuxwdog watchdog server.

%prep

%setup -q -n %{name}-%{version}

%build
ant \
    -Dproduct.ui.flavor.prefix="" \
    -Dproduct.prefix="" \
    -Dproduct="nuxwdog" \
    -Dversion="%{version}"
%configure \
%ifarch ppc64 s390x sparc64 x86_64
    --enable-64bit \
%endif
    --libdir=%{_libdir}
make

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}

## rearrange files to be in the desired native packaging layout
if [ -d %{buildroot}/usr/local ]; then
    cp -r %{buildroot}/usr/local/* %{buildroot}/usr
    rm -rf %{buildroot}/usr/local
fi
mkdir -p  %{buildroot}/usr/share/doc
mv %{buildroot}/usr/doc %{buildroot}/usr/share/doc/%{name}-%{version}

find %{buildroot}/%{perl_vendorarch} -name .packlist |xargs rm -f {}
find %{buildroot}/%{perl_vendorarch} -name "*.bs" |xargs rm -f {}
find %{buildroot} -name "perllocal.pod" |xargs rm -f {}
find %{buildroot}/%{perl_vendorarch} -name "Nuxwdogclient.so" |xargs chmod 755
find %{buildroot}/%{perl_vendorarch} -name "Nuxwdogclient.pm" |xargs chmod 644

#get perl filelist
find %{buildroot}/%{perl_vendorarch} -type f -print |
    sed  "s@^%{buildroot}@@g" > %{name}-%{version}-%{release}-perl-filelist
find %{buildroot}/%{perl_vendorarch} -type d -name Nuxwdogclient |
    sed  "s@^%{buildroot}@@g" >> %{name}-%{version}-%{release}-perl-filelist

rm %{buildroot}/%{_libdir}/*.la
mkdir -p %{buildroot}/%{_libdir}/nuxwdog-jni
mv %{buildroot}/%{_libdir}/libnuxwdog-jni.so  %{buildroot}/%{_libdir}/nuxwdog-jni
mv %{buildroot}/usr/jars/nuxwdog.jar %{buildroot}/%{_libdir}/nuxwdog-jni/nuxwdog-%{version}.jar
mkdir -p %{buildroot}%{_jnidir}/
cd %{buildroot}/%{_jnidir}; ln -s %{_libdir}/nuxwdog-jni/nuxwdog-%{version}.jar nuxwdog.jar
rm -rf %{buildroot}/usr/jars
rm -rf %{buildroot}/usr/doc

%post -p /sbin/ldconfig 

%postun -p /sbin/ldconfig

%post client -p /sbin/ldconfig 
 
%postun client -p /sbin/ldconfig
 

%clean
rm -rf ${RPM_BUILD_ROOT}

%files
%defattr(-,root,root)
%doc LICENSE
%{_bindir}/*

%files client
%defattr(-,root,root)
%{_libdir}/libnuxwdog.so.*

%files client-devel
%defattr(-,root,root)
%{_includedir}/nuxwdog/
%{_libdir}/libnuxwdog.so

%files client-java
%defattr(-,root,root)
%{_libdir}/nuxwdog-jni/
%{_jnidir}/*

%files client-perl -f %{name}-%{version}-%{release}-perl-filelist
%defattr(-,root,root)
%{_datadir}/man/man3/Nuxwdogclient.3pm.gz


%changelog
* Thu Feb 11 2010 Ade Lee <alee@redhat.com> 1.0.0-2
- Initial version in separated repo.

* Tue Dec 1 2009 Ade Lee <alee@redhat.com> 1.0.0-1
- Initial open source version based upon Red Hat
  Certificate System (RHCS) 6.1 uxwdog code.

