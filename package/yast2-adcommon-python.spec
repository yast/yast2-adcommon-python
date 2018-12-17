#
# spec file for package yast2-adcommon-python
#
# Copyright (c) 2018 SUSE LINUX GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#


Name:           yast2-adcommon-python
Version:        1.0
Release:        0
Summary:        Common code for the yast python ad modules
License:        GPL-3.0+
Group:          Productivity/Networking/Samba
Url:            https://github.com/dmulder/yast2-adcommon-python
Source:         %{name}-%{version}.tar.bz2
BuildArch:      noarch
Requires:       krb5-client
Requires:       samba-client
Requires:       samba-python3
Requires:       yast2
Requires:       yast2-python3-bindings >= 4.0.0
Requires:       python3-ldap
BuildRequires:	python3

%description
Common code shared by the yast2-aduc, yast2-adsi, and yast2-gpmc modules.

%prep
%setup -q

%build
autoreconf -if
%configure --prefix=%{_prefix}
make

%install
make DESTDIR=$RPM_BUILD_ROOT install

%clean
%{__rm} -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)

%changelog
