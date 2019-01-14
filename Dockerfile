FROM alpine:3.8

ENV \
	LC_ALL=en_US.UTF-8 \
	LANG=en_US.UTF-8 \
	LANGUAGE=en_US.UTF-8

RUN \
	# Node: build our own since Kibana's doesn't work on Alpine,
	# and apk's version isn't compatible with the Kibana version
	# needed for GDS PaaS Elasticsearch
	apk add --no-cache --virtual .node-build-deps \
		build-base=.5-r1 \
		gnupg=2.2.8-r0 \
		linux-headers=4.4.6-r2 \
		python2=2.7.15-r1 \
		wget=1.20.1-r0 && \
	NODE_VERSION=v8.11.4 && \
	NODE_BASE_URL=https://nodejs.org/dist/${NODE_VERSION}/ && \
	for server in ipv4.pool.sks-keyservers.net keyserver.pgp.com ha.pool.sks-keyservers.net; do \
		# List of keys from https://github.com/nwjs/node
		gpg --keyserver $server --recv-keys \
			4ED778F539E3634C779C87C6D7062848A1AB005C \
			B9E2F5981AA6E0CD28160D9FF13993A75599653C \
			94AE36675C464D64BAFA68DD7434390BDBE9B9C5 \
			B9AE9905FFD7803F25714661B63B535A4C206CA9 \
			77984A986EBC2AA786BC0F66B01FBB92821C587A \
			71DCFD284A79C3B38668286BC97EC7A07EDE3FC1 \
			FD3A5288F042B6850C66B31F09FE44734EB7990E \
			8FCCA13FEF1D0C2E91008E09770F7A9A5AE15600 \
			C4F0DFFF4E8C1A8236409D08E73BC641CC11F4C8 \
			DD8F2338BAE7501E3DD5AC78C273792F7D83545D \
			A48C2BEE680E841632CD4E44F07496B3EB3C1762 && break; \
		  done && \
	wget "${NODE_BASE_URL}node-${NODE_VERSION}.tar.xz" && \
	wget -O - "${NODE_BASE_URL}SHASUMS256.txt.asc" \
		| gpg --batch --decrypt \
		| grep " node-${NODE_VERSION}.tar.xz\$" \
		| sha256sum -c \
		| grep ': OK$' && \
	tar -xf node-${NODE_VERSION}.tar.xz && \
	( \
		cd node-${NODE_VERSION} && \
		./configure --prefix=/usr --fully-static --without-npm && \
		make -j$(getconf _NPROCESSORS_ONLN) && \
		make install \
	) && \
	rm -r -f node-${NODE_VERSION} && \
	rm -r -f node-${NODE_VERSION}.tar.xz && \
	apk del --purge \
		.node-build-deps

RUN \
	# Kibana
	apk add --no-cache --virtual .kibana-build-deps \
		gnupg=2.2.8-r0 \
		wget=1.20.1-r0 && \
	KIBANA_VERSION=6.4.3-linux-x86_64 && \
	KIBANA_BASE_URL=https://artifacts.elastic.co && \
	KIBANA_TARBALL=kibana-oss-${KIBANA_VERSION}.tar.gz && \
	KIBANA_TARBALL_ASC=kibana-oss-${KIBANA_VERSION}.tar.gz.asc && \
	KIBANA_GPG_KEY=GPG-KEY-elasticsearch && \
	KIBANA_GPG_KEY_FINGERPRINT="4609 5ACC 8548 582C 1A26  99A9 D27D 666C D88E 42B4" && \
	wget "${KIBANA_BASE_URL}/downloads/kibana/${KIBANA_TARBALL}" && \
	wget "${KIBANA_BASE_URL}/downloads/kibana/${KIBANA_TARBALL_ASC}" && \
	wget "${KIBANA_BASE_URL}/${KIBANA_GPG_KEY}" && \
	export KIBANA_GNUPGHOME="$(mktemp -d)" && \
	gpg --import "${KIBANA_GPG_KEY}" && \
	gpg --fingerprint | grep "${KIBANA_GPG_KEY_FINGERPRINT}" && \
	gpg --batch --verify "${KIBANA_TARBALL_ASC}" "${KIBANA_TARBALL}" && \
	tar -xzf "${KIBANA_TARBALL}" && \
	mv "kibana-${KIBANA_VERSION}" /usr/share/kibana && \
	rm -rf "${KIBANA_GNUPGHOME}" "${KIBANA_TARBALL}" "${KIBANA_TARBALL_ASC}" && \
	rm -r -f /usr/share/kibana/node/ && \
	apk add --no-cache \
		jq=1.6_rc1-r1 && \
	apk del --purge \
		.kibana-build-deps

COPY requirements.txt /

RUN \
	# SSO proxy
	apk add --no-cache --virtual .sso-proxy-build-deps \
		build-base=.5-r1 && \
	apk add --no-cache \
		python3-dev=3.6.6-r0 \
		python3=3.6.6-r0 && \
	pip3 install -r requirements.txt && \
	apk del --purge \
		.sso-proxy-build-deps

COPY sso-proxy.py /

# PaaS requires this
EXPOSE 8080

# PaaS appears to require this entrypoint
COPY entrypoint.sh /usr/local/bin/docker_entrypoint.sh
ENTRYPOINT ["/usr/local/bin/docker_entrypoint.sh"]

RUN \
	adduser -D kibana

USER kibana
