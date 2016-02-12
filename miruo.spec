Name:           miruo
Version:        0.9.6
Release:        1%{?dist}
Summary:        Packet capture type tcp session monitor

Group:          Applications/Internet
License:        GPLv3
URL:            https://github.com/KLab/miruo
Source0:        https://github.com/KLab/miruo/%{name}-%{version}.tar.gz

BuildRequires:  gcc,libpcap-devel
Requires:       libpcap

%description
miruo is a packet capture type TCP session monitor.
miruo can
- show packets grouped by TCP sessions
- show only connect-disconnect info in simple & neat style
- show TCP sessions with which segments were resent
- show TCP sessions which exceeds certain time.
- show TCP sessions which were terminated by RST
- show segments where IP fragmentation occured
- utilize files saved by tcpdump -w
- is light & run with high speed

%prep
%setup -q

%build
%configure
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_sbindir}/miruo

%changelog
* Fri Feb 12 2016 Shota Ito <st.1t@hotmail.co.jp>
- Initial miruo spec file
