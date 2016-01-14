SUBDIRS = src test

PACKAGE_NAME=rtset
GIT_RPM_VERSION=./git-rpm-version/git-rpm-version
PACKAGE_VERSION=$(shell $(GIT_RPM_VERSION) -v 2>/dev/null)
PACKAGE_RELEASE=$(shell $(GIT_RPM_VERSION) -r 2>/dev/null)
PACKAGE_NAME_VERSION=$(PACKAGE_NAME)-$(PACKAGE_VERSION)
PACKAGE_NAME_VERSION_RELEASE=$(PACKAGE_NAME_VERSION)-$(PACKAGE_RELEASE)
SPEC_FILE_IN=$(PACKAGE_NAME).spec.in
SPEC_FILE=$(PACKAGE_NAME).spec
WORKDIR=$(shell pwd -P)/workdir
TARBALL=$(WORKDIR)/SOURCES/$(PACKAGE_NAME_VERSION_RELEASE).tar.gz
SRPM=$(WORKDIR)/SRPMS/$(PACKAGE_NAME_VERSION_RELEASE).*.src.rpm
ARCH=$(shell uname -m)
RPM=$(WORKDIR)/RPMS/$(ARCH)/$(PACKAGE_NAME_VERSION_RELEASE).*.rpm
ALL_RPMS=$(WORKDIR)/RPMS/$(ARCH)/$(PACKAGE_NAME_VERSION_RELEASE)*.rpm
SOURCES=$(shell git ls-files)
RPMBUILD=rpmbuild

$(GIT_RPM_VERSION):
	$(error git-rpm-versios submodule is missing \
	        (use "git submodule update --init" \
	        to clone the missing submodules))

$(SPEC_FILE): $(SPEC_FILE_IN) $(GIT_RPM_VERSION)
	sed -e 's/^%define ver VERSION.*/%define ver $(PACKAGE_VERSION)/' \
	    -e 's/^%define rel RELEASE.*/%define rel $(PACKAGE_RELEASE)/' \
	    $(SPEC_FILE_IN) > $(SPEC_FILE)

.PHONY: tarball
.SECONDARY: $(TARBALL) # rpmbuild removes this tarball
$(TARBALL): $(SPEC_FILE) $(SOURCES)
	mkdir -p $(WORKDIR)/{SPECS,RPMS,SRPMS,SOURCES,BUILD,BUILDROOT}
	tar zcf $(TARBALL) --transform 's,^,$(PACKAGE_NAME_VERSION)/,' \
	    $(SOURCES) $(SPEC_FILE)

.PHONY: srpm
srpm: $(SRPM)
$(SRPM): $(TARBALL)
	$(RPMBUILD) -ts --define="_topdir $(WORKDIR)" $(TARBALL)

.PHONY: rpm
rpm: $(RPM)
$(RPM): $(SRPM)
	$(RPMBUILD) --define="_topdir $(WORKDIR)" --rebuild $(SRPM)

clean-local:
	-rm -rf $(WORKDIR) $(SPEC_FILE)
